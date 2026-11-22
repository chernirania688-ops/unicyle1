const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new DatabaseSync(path.join(dataDir, 'unicycle.db'));
db.exec('PRAGMA journal_mode = WAL;');
// Transaction : tout réussit ou rien n'est enregistré
db.transaction = fn => (...a) => {
  db.exec('BEGIN IMMEDIATE');
  try { const r = fn(...a); db.exec('COMMIT'); return r; }
  catch (e) { db.exec('ROLLBACK'); throw e; }
};

let SECRET = process.env.JWT_SECRET;
if (!SECRET) {
  const f = path.join(dataDir, '.secret');
  if (!fs.existsSync(f)) fs.writeFileSync(f, crypto.randomBytes(32).toString('hex'));
  SECRET = fs.readFileSync(f, 'utf8');
}

db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, hash TEXT NOT NULL,
  name TEXT NOT NULL, campus TEXT NOT NULL, residence TEXT DEFAULT '', courier INTEGER DEFAULT 0, created INTEGER);
CREATE TABLE IF NOT EXISTS listings(
  id INTEGER PRIMARY KEY, seller_id INTEGER NOT NULL, title TEXT NOT NULL, descr TEXT NOT NULL,
  cat TEXT NOT NULL, cond TEXT NOT NULL, price REAL NOT NULL, campus TEXT NOT NULL,
  status TEXT DEFAULT 'dispo', created INTEGER);
CREATE TABLE IF NOT EXISTS orders(
  id INTEGER PRIMARY KEY, listing_id INTEGER NOT NULL, title TEXT NOT NULL, price REAL NOT NULL, fee REAL NOT NULL,
  mode TEXT NOT NULL, buyer_id INTEGER NOT NULL, seller_id INTEGER NOT NULL, courier_id INTEGER,
  status TEXT DEFAULT 'sequestre', created INTEGER, updated INTEGER);
CREATE TABLE IF NOT EXISTS notifs(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, text TEXT NOT NULL, order_id INTEGER, seen INTEGER DEFAULT 0, created INTEGER);
CREATE TABLE IF NOT EXISTS claims(
  id INTEGER PRIMARY KEY, order_id INTEGER UNIQUE NOT NULL, reason TEXT NOT NULL, details TEXT DEFAULT '',
  status TEXT DEFAULT 'ouverte', response TEXT DEFAULT '', created INTEGER, updated INTEGER);
`);
// Migration : colonne photo pour les bases créées avant cette version
if (!db.prepare('PRAGMA table_info(listings)').all().some(c => c.name === 'photo')) db.exec('ALTER TABLE listings ADD COLUMN photo TEXT');

const CATS = ['Livres', 'Calculatrices', 'Matériel TP', 'Mobilier', 'Électroménager', 'Kits Rentrée / TP'];
const FEES = { main: 0, livreur: 3, relais: 2 };
const CLAIM_REASONS = ['Non conforme à l’annonce', 'Défectueux ou ne fonctionne pas', 'Abîmé', 'Ne me convient pas', 'Autre'];
const CLAIM_WINDOW = 7 * 864e5, MODE_LABEL = { main: 'remise en main propre', livreur: 'livraison par un étudiant', relais: 'point relais' };
const COMMISSION = 0.08, COURIER_SHARE = 0.8, AUTO_RELEASE_MS = 48 * 3600 * 1000;
const now = () => Date.now();
const fail = (msg, status = 400) => { throw Object.assign(new Error(msg), { status }); };
const pub = u => ({ id: u.id, email: u.email, name: u.name, campus: u.campus, residence: u.residence, courier: !!u.courier });

const eur = n => n.toFixed(2).replace('.', ',') + ' €';
const notify = (uid, text, oid = null) => db.prepare('INSERT INTO notifs(user_id,text,order_id,created) VALUES(?,?,?,?)').run(uid, text, oid, now());

const app = express();
app.use(express.json({ limit: '700kb' }));

const wrap = f => (req, res) => {
  try { const out = f(req, res); res.json(out === undefined ? { ok: true } : out); }
  catch (e) { res.status(e.status || 400).json({ error: e.message }); }
};

const auth = (req, res, next) => {
  try {
    const m = /(?:^|; )token=([^;]+)/.exec(req.headers.cookie || '');
    const p = jwt.verify(m && m[1], SECRET);
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(p.id);
    if (!u) throw 0;
    req.user = u; next();
  } catch { res.status(401).json({ error: 'Connexion requise' }); }
};

const login = (res, u) => {
  const t = jwt.sign({ id: u.id }, SECRET, { expiresIn: '30d' });
  res.cookie('token', t, { httpOnly: true, sameSite: 'lax', maxAge: 30 * 864e5, secure: process.env.NODE_ENV === 'production' });
};

// Limiteur simple contre les essais répétés de connexion
const tries = new Map();
const limit = (req) => {
  const k = req.ip, t = tries.get(k) || { n: 0, at: now() };
  if (now() - t.at > 15 * 60e3) { t.n = 0; t.at = now(); }
  if (++t.n > 10) fail('Trop de tentatives. Réessaie dans 15 minutes.', 429);
  tries.set(k, t);
};

// --- Comptes ---
app.post('/api/register', wrap((req, res) => {
  limit(req);
  const { email, password, name, campus, residence, courier } = req.body || {};
  if (!/^\S+@\S+\.\S+$/.test(email || '')) fail('E-mail invalide');
  if (!password || password.length < 8) fail('Mot de passe : 8 caractères minimum');
  if (!name?.trim() || !campus?.trim()) fail('Prénom et campus obligatoires');
  const e = email.trim().toLowerCase();
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(e)) fail('Un compte existe déjà avec cet e-mail', 409);
  const id = db.prepare('INSERT INTO users(email,hash,name,campus,residence,courier,created) VALUES(?,?,?,?,?,?,?)')
    .run(e, bcrypt.hashSync(password, 10), name.trim(), campus.trim(), (residence || '').trim(), courier ? 1 : 0, now()).lastInsertRowid;
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(id);
  login(res, u); return pub(u);
}));

app.post('/api/login', wrap((req, res) => {
  limit(req);
  const { email, password } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(String(email || '').trim().toLowerCase());
  if (!u || !bcrypt.compareSync(String(password || ''), u.hash)) fail('E-mail ou mot de passe incorrect', 401);
  login(res, u); return pub(u);
}));

app.post('/api/logout', wrap((req, res) => { res.clearCookie('token'); }));
app.get('/api/me', auth, wrap(req => pub(req.user)));
app.put('/api/me', auth, wrap(req => {
  const b = req.body || {}, u = req.user;
  db.prepare('UPDATE users SET name=?,campus=?,residence=?,courier=? WHERE id=?')
    .run((b.name ?? u.name).trim() || u.name, (b.campus ?? u.campus).trim() || u.campus, (b.residence ?? u.residence).trim(), b.courier === undefined ? u.courier : (b.courier ? 1 : 0), u.id);
  return pub(db.prepare('SELECT * FROM users WHERE id=?').get(u.id));
}));

// --- Annonces ---
const LQ = `SELECT l.id,l.seller_id,l.title,l.descr,l.cat,l.cond,l.price,l.campus,l.status,l.created,(l.photo IS NOT NULL) AS has_photo, u.name AS seller_name FROM listings l JOIN users u ON u.id=l.seller_id`;
app.get('/api/listings', auth, wrap(req => {
  const { q = '', cat = '', campus = '' } = req.query;
  return db.prepare(`${LQ} WHERE l.status='dispo' ORDER BY l.created DESC`).all()
    .filter(l => (!cat || l.cat === cat) && (!campus || l.campus === campus) && (!q || (l.title + ' ' + l.descr).toLowerCase().includes(String(q).toLowerCase())))
    .map(l => ({ ...l, mine: l.seller_id === req.user.id }));
}));
app.get('/api/listings/mine', auth, wrap(req =>
  db.prepare(`${LQ} WHERE l.seller_id=? AND l.status!='retiree' ORDER BY l.created DESC`).all(req.user.id)));
app.post('/api/listings', auth, wrap(req => {
  const b = req.body || {}, price = Number(b.price);
  if (!b.title?.trim() || !b.descr?.trim()) fail('Titre et description obligatoires');
  if (!CATS.includes(b.cat)) fail('Catégorie invalide');
  if (!(price >= 1 && price <= 5000)) fail('Prix invalide (1 à 5000 €)');
  const photo = typeof b.photo === 'string' && b.photo.length <= 450000 && /^data:image\/jpeg;base64,[A-Za-z0-9+\/=]+$/.test(b.photo) ? b.photo : null;
  const id = db.prepare('INSERT INTO listings(seller_id,title,descr,cat,cond,price,campus,created,photo) VALUES(?,?,?,?,?,?,?,?,?)')
    .run(req.user.id, b.title.trim().slice(0, 60), b.descr.trim().slice(0, 240), b.cat, String(b.cond || 'Bon état').slice(0, 30), price, (b.campus || req.user.campus).trim(), now(), photo).lastInsertRowid;
  return { id };
}));
app.delete('/api/listings/:id', auth, wrap(req => {
  const r = db.prepare(`UPDATE listings SET status='retiree' WHERE id=? AND seller_id=? AND status='dispo'`).run(req.params.id, req.user.id);
  if (!r.changes) fail('Annonce introuvable ou déjà réservée', 404);
}));

app.get('/api/listings/:id/photo', auth, (req, res) => {
  const r = db.prepare('SELECT photo FROM listings WHERE id=?').get(req.params.id);
  if (!r || !r.photo) return res.status(404).end();
  res.set({ 'Content-Type': 'image/jpeg', 'Cache-Control': 'private, max-age=86400' });
  res.send(Buffer.from(r.photo.split(',')[1], 'base64'));
});

// --- Commandes (paiement en séquestre simulé) ---
const OQ = `SELECT o.*, b.name AS buyer_name, s.name AS seller_name, c.name AS courier_name,
  cl.status AS claim_status, cl.reason AS claim_reason, cl.details AS claim_details, cl.response AS claim_response,
  (SELECT photo IS NOT NULL FROM listings WHERE id=o.listing_id) AS has_photo FROM orders o
  JOIN users b ON b.id=o.buyer_id JOIN users s ON s.id=o.seller_id LEFT JOIN users c ON c.id=o.courier_id LEFT JOIN claims cl ON cl.order_id=o.id`;
const createOrder = db.transaction((uid, lid, mode) => {
  const l = db.prepare(`SELECT * FROM listings WHERE id=? AND status='dispo'`).get(lid);
  if (!l) fail('Annonce indisponible', 409);
  if (l.seller_id === uid) fail('Tu ne peux pas acheter ta propre annonce');
  if (!(mode in FEES)) fail('Mode de remise invalide');
  const t = now();
  const id = db.prepare('INSERT INTO orders(listing_id,title,price,fee,mode,buyer_id,seller_id,created,updated,status) VALUES(?,?,?,?,?,?,?,?,?,\'attente\')')
    .run(l.id, l.title, l.price, FEES[mode], mode, uid, l.seller_id, t, t).lastInsertRowid;
  db.prepare(`UPDATE listings SET status='reserve' WHERE id=?`).run(l.id);
  return id;
});
app.post('/api/orders', auth, wrap(req => {
  const id = createOrder(req.user.id, Number(req.body?.listingId) || 0, String(req.body?.mode || ''));
  const o = db.prepare('SELECT * FROM orders WHERE id=?').get(id);
  notify(o.seller_id, `${req.user.name} veut acheter « ${o.title} » à ${eur(o.price)} (${MODE_LABEL[o.mode]}). Confirmer la vente ?`, id);
  return { id };
}));

app.get('/api/orders', auth, wrap(req => {
  const u = req.user.id;
  const mine = db.prepare(`${OQ} WHERE o.buyer_id=? OR o.seller_id=? OR o.courier_id=? ORDER BY o.created DESC`).all(u, u, u);
  const missions = req.user.courier
    ? db.prepare(`${OQ} WHERE o.mode!='main' AND o.status='sequestre' AND o.courier_id IS NULL AND o.buyer_id!=? AND o.seller_id!=? ORDER BY o.created DESC`).all(u, u) : [];
  return { orders: mine, missions };
}));

const release = db.transaction((o) => {
  db.prepare(`UPDATE orders SET status='livre', updated=? WHERE id=?`).run(now(), o.id);
  db.prepare(`UPDATE listings SET status='vendu' WHERE id=?`).run(o.listing_id);
});
const mineOrder = (req, role) => {
  const o = db.prepare('SELECT * FROM orders WHERE id=?').get(req.params.id);
  if (!o || o[role] !== req.user.id) fail('Commande introuvable', 404);
  return o;
};
app.post('/api/orders/:id/confirm', auth, wrap(req => {
  const o = mineOrder(req, 'buyer_id');
  if (!['sequestre', 'enroute'].includes(o.status)) fail('Commande déjà clôturée');
  release(o);
  notify(o.seller_id, `${req.user.name} a confirmé la réception de « ${o.title} ». Tu reçois ${eur(o.price * (1 - COMMISSION))}.`, o.id);
}));
app.post('/api/orders/:id/dispute', auth, wrap(req => {
  const o = mineOrder(req, 'buyer_id');
  if (!['sequestre', 'enroute'].includes(o.status)) fail('Commande déjà clôturée');
  db.prepare(`UPDATE orders SET status='litige', updated=? WHERE id=?`).run(now(), o.id);
}));
app.post('/api/orders/:id/take', auth, wrap(req => {
  if (!req.user.courier) fail('Active le mode livreur dans ton compte', 403);
  const r = db.prepare(`UPDATE orders SET courier_id=?, status='enroute', updated=? WHERE id=? AND courier_id IS NULL AND status='sequestre' AND mode!='main' AND buyer_id!=? AND seller_id!=?`)
    .run(req.user.id, now(), req.params.id, req.user.id, req.user.id);
  if (!r.changes) fail('Mission déjà prise ou indisponible', 409);
}));

// --- Confirmation de la vente par le vendeur ---
const closeOrder = db.transaction((o, status) => {
  db.prepare('UPDATE orders SET status=?, updated=? WHERE id=?').run(status, now(), o.id);
  db.prepare(`UPDATE listings SET status='dispo' WHERE id=?`).run(o.listing_id);
});
app.post('/api/orders/:id/accept', auth, wrap(req => {
  const o = mineOrder(req, 'seller_id');
  if (o.status !== 'attente') fail('Commande déjà traitée');
  db.prepare(`UPDATE orders SET status='sequestre', updated=? WHERE id=?`).run(now(), o.id);
  notify(o.buyer_id, `${req.user.name} a confirmé la vente de « ${o.title} ». Ton paiement est bloqué en séquestre jusqu’à la réception.`, o.id);
}));
app.post('/api/orders/:id/refuse', auth, wrap(req => {
  const o = mineOrder(req, 'seller_id');
  if (o.status !== 'attente') fail('Commande déjà traitée');
  closeOrder(o, 'refuse');
  notify(o.buyer_id, `${req.user.name} a refusé la vente de « ${o.title} ». Tu n’as rien payé.`, o.id);
}));
app.post('/api/orders/:id/cancel', auth, wrap(req => {
  const o = mineOrder(req, 'buyer_id');
  if (o.status !== 'attente') fail('Le vendeur a déjà répondu : utilise le litige si besoin');
  closeOrder(o, 'annule');
  notify(o.seller_id, `${req.user.name} a annulé sa demande d’achat de « ${o.title} ».`, o.id);
}));

// --- Réclamation après vente (7 jours après la réception) ---
app.post('/api/orders/:id/claim', auth, wrap(req => {
  const o = mineOrder(req, 'buyer_id'), { reason, details } = req.body || {};
  if (o.status !== 'livre') fail('Réclamation possible seulement après la réception');
  if (now() - o.updated > CLAIM_WINDOW) fail('Le délai de 7 jours est dépassé');
  if (!CLAIM_REASONS.includes(reason)) fail('Motif invalide');
  if (db.prepare('SELECT 1 FROM claims WHERE order_id=?').get(o.id)) fail('Une réclamation existe déjà pour cette commande', 409);
  db.prepare('INSERT INTO claims(order_id,reason,details,created,updated) VALUES(?,?,?,?,?)').run(o.id, reason, String(details || '').slice(0, 300), now(), now());
  notify(o.seller_id, `${req.user.name} a ouvert une réclamation sur « ${o.title} » : ${reason}. Tu peux accepter le remboursement ou refuser.`, o.id);
}));
const answerClaim = db.transaction((o, accept, response) => {
  db.prepare('UPDATE claims SET status=?, response=?, updated=? WHERE order_id=?').run(accept ? 'acceptee' : 'refusee', response, now(), o.id);
  if (accept) db.prepare(`UPDATE orders SET status='rembourse', updated=? WHERE id=?`).run(now(), o.id);
});
app.post('/api/orders/:id/claim/respond', auth, wrap(req => {
  const o = mineOrder(req, 'seller_id');
  const cl = db.prepare('SELECT * FROM claims WHERE order_id=?').get(o.id);
  if (!cl || cl.status !== 'ouverte') fail('Aucune réclamation en attente');
  const accept = !!req.body?.accept;
  answerClaim(o, accept, String(req.body?.response || '').slice(0, 300));
  notify(o.buyer_id, accept ? `${req.user.name} a accepté ta réclamation sur « ${o.title} » : tu es remboursé de ${eur(o.price + o.fee)}.` : `${req.user.name} a refusé ta réclamation sur « ${o.title} ».`, o.id);
}));

// --- Messages ---
app.get('/api/notifs', auth, wrap(req => db.prepare('SELECT * FROM notifs WHERE user_id=? ORDER BY created DESC, id DESC LIMIT 50').all(req.user.id)));
app.post('/api/notifs/read', auth, wrap(req => { db.prepare('UPDATE notifs SET seen=1 WHERE user_id=?').run(req.user.id); }));

// Libération automatique après 48 h sans litige (commandes en cours de livraison)
const autoRelease = () => db.prepare(`SELECT * FROM orders WHERE status='enroute' AND updated<?`).all(now() - AUTO_RELEASE_MS).forEach(o => release(o));
setInterval(autoRelease, 10 * 60e3).unref();

app.use('/api', (req, res) => res.status(404).json({ error: 'Route inconnue' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use((err, req, res, next) => res.status(err.status || 400).json({ error: err.status === 413 ? 'Fichier trop volumineux' : 'Requête invalide' }));
app.listen(PORT, () => console.log(`UniCycle sur http://localhost:${PORT}`));
module.exports = app;
