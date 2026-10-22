/* ERA – La Voie des Otaku · serveur
   REST : /api/register /login /me /save /hero /logout /code /account /admin
   WebSocket : /ws?t=TOKEN  (chat, positions, classement, duels 1v1, PvP)
   Variables d'environnement : PORT, ADMIN_CODE (code admin, par défaut OASIS), DATA_DIR (dossier de données) */
const express = require('express'), http = require('http'), crypto = require('crypto'), fs = require('fs'), path = require('path');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000, ADMIN_CODE = process.env.ADMIN_CODE || 'OASIS';
const DIR = process.env.DATA_DIR || path.join(__dirname, 'data'), FILE = path.join(DIR, 'db.json');
fs.mkdirSync(DIR, { recursive: true });

/* ---------- base de données (fichier JSON, écriture différée) ---------- */
let db = { users: {}, sessions: {}, board: [] };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(FILE, 'utf8'))); } catch (e) {}
let saveT = null;
const persist = () => { clearTimeout(saveT); saveT = setTimeout(() => { try { fs.writeFileSync(FILE + '.tmp', JSON.stringify(db)); fs.renameSync(FILE + '.tmp', FILE); } catch (e) { console.error('save', e.message); } }, 800); };
process.on('SIGTERM', () => { try { fs.writeFileSync(FILE, JSON.stringify(db)); } catch (e) {} process.exit(0); });

/* ---------- utilitaires ---------- */
const key = u => u.toLowerCase();
const hash = (c, salt) => crypto.scryptSync(c, salt, 32).toString('hex');
const same = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const okName = u => typeof u === 'string' && /^[\p{L}\p{N}_\-. ]{3,16}$/u.test(u.trim());
const okCode = c => typeof c === 'string' && c.length >= 4 && c.length <= 32;
const newToken = u => { const t = crypto.randomBytes(24).toString('hex'); db.sessions[t] = { u: key(u), exp: Date.now() + 90 * 864e5 }; persist(); return t; };
const clean = (s, n) => String(s == null ? '' : s).replace(/[\u0000-\u001f<>]/g, '').slice(0, n);
const tries = new Map();
const limited = ip => { const now = Date.now(), r = (tries.get(ip) || []).filter(t => now - t < 60000); r.push(now); tries.set(ip, r); return r.length > 12; };

/* ---------- API REST ---------- */
const app = express();
app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.set({ 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS', 'Access-Control-Max-Age': '86400' });
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json({ limit: '4mb' }));

const auth = (req, res, next) => {
  const t = (req.get('Authorization') || '').replace(/^Bearer\s+/i, ''), s = db.sessions[t];
  if (!s || s.exp < Date.now() || !db.users[s.u]) return res.status(401).json({ e: 'Session expirée' });
  req.tok = t; req.k = s.u; req.user = db.users[s.u]; next();
};

app.post('/api/register', (req, res) => {
  if (limited(req.ip)) return res.status(429).json({ e: 'Trop de tentatives, réessaie dans une minute.' });
  const { u, c } = req.body || {};
  if (!okName(u)) return res.status(400).json({ e: 'Nom invalide : 3 à 16 caractères (lettres, chiffres, _ - .).' });
  if (!okCode(c)) return res.status(400).json({ e: 'Code invalide : 4 à 32 caractères.' });
  const name = u.trim(), k = key(name);
  if (db.users[k]) return res.status(409).json({ e: 'Ce nom est déjà pris.' });
  const salt = crypto.randomBytes(16).toString('hex');
  db.users[k] = { name, salt, h: hash(c, salt), ls: {}, created: Date.now() };
  res.json({ t: newToken(name), u: name, ls: {} });
});

app.post('/api/login', (req, res) => {
  if (limited(req.ip)) return res.status(429).json({ e: 'Trop de tentatives, réessaie dans une minute.' });
  const { u, c } = req.body || {}, us = typeof u === 'string' && db.users[key(u.trim())];
  if (!us || typeof c !== 'string' || !same(us.h, hash(c, us.salt))) return res.status(401).json({ e: 'Nom ou code incorrect.' });
  res.json({ t: newToken(us.name), u: us.name, ls: us.ls });
});

app.get('/api/me', auth, (req, res) => res.json({ u: req.user.name, ls: req.user.ls }));

app.put('/api/save', auth, (req, res) => {
  const ls = req.body && req.body.ls;
  if (!ls || typeof ls !== 'object') return res.status(400).json({ e: 'Données invalides' });
  const out = {};
  for (const k in ls) if (/^pl_[\w-]{1,60}$/.test(k) && typeof ls[k] === 'string') out[k] = ls[k];
  req.user.ls = out; persist(); res.json({ ok: true });
});

app.delete('/api/hero', auth, (req, res) => { req.user.ls = {}; persist(); res.json({ ok: true }); });
app.post('/api/logout', auth, (req, res) => { delete db.sessions[req.tok]; persist(); res.json({ ok: true }); });

app.post('/api/code', auth, (req, res) => {
  const { o, n } = req.body || {};
  if (typeof o !== 'string' || !same(req.user.h, hash(o, req.user.salt))) return res.status(401).json({ e: 'Code actuel incorrect.' });
  if (!okCode(n)) return res.status(400).json({ e: 'Nouveau code : 4 à 32 caractères.' });
  req.user.salt = crypto.randomBytes(16).toString('hex'); req.user.h = hash(n, req.user.salt);
  for (const t in db.sessions) if (db.sessions[t].u === req.k && t !== req.tok) delete db.sessions[t];
  persist(); res.json({ ok: true });
});

app.delete('/api/account', auth, (req, res) => {
  const { c } = req.body || {};
  if (typeof c !== 'string' || !same(req.user.h, hash(c, req.user.salt))) return res.status(401).json({ e: 'Code incorrect.' });
  delete db.users[req.k];
  for (const t in db.sessions) if (db.sessions[t].u === req.k) delete db.sessions[t];
  persist(); res.json({ ok: true });
});

app.post('/api/admin', auth, (req, res) => {
  if (limited(req.ip)) return res.status(429).json({ e: 'Trop de tentatives.' });
  const c = String((req.body || {}).c || '');
  if (!ADMIN_CODE) return res.status(403).json({ e: 'Admin désactivé sur ce serveur.' });
  res.json({ ok: same(c, ADMIN_CODE) });
});

app.get('/health', (req, res) => res.send('ok'));
app.use(express.static(path.join(__dirname, 'public')));

/* ---------- WebSocket : chat, foule, classement, duels ---------- */
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 8192 });
let nextId = 1; const clients = new Set(), queue = [], history = [];

const send = (w, o) => { if (w && w.readyState === 1) try { w.send(JSON.stringify(o)); } catch (e) {} };
const all = (o, except) => { const s = JSON.stringify(o); for (const c of clients) if (c !== except && c.readyState === 1) try { c.send(s); } catch (e) {} };
const sortBoard = () => { db.board.sort((a, b) => (b.win | 0) - (a.win | 0) || b.w - a.w || a.t - b.t); db.board.length = Math.min(db.board.length, 50); };
const unqueue = w => { const i = queue.indexOf(w); if (i >= 0) queue.splice(i, 1); };
const endDuel = (w, notify) => { const o = w.foe; if (o) { o.foe = null; w.foe = null; if (notify) send(o, { t: 'dx' }); } };

wss.on('connection', (ws, req) => {
  const t = new URL(req.url, 'http://x').searchParams.get('t'), s = db.sessions[t];
  if (!s || s.exp < Date.now() || !db.users[s.u]) return ws.close(4001, 'auth');
  ws.id = nextId++; ws.alive = true; ws.last = 0; ws.pos = null; ws.foe = null; ws.name = db.users[s.u].name;
  clients.add(ws);
  send(ws, { t: 'hello', board: db.board, n: clients.size, history: history.slice(-30), players: [...clients].filter(c => c !== ws && c.pos).map(c => c.pos) });
  all({ t: 'online', n: clients.size });
  ws.on('pong', () => { ws.alive = true; });

  ws.on('message', raw => {
    let d; try { d = JSON.parse(raw); } catch (e) { return; }
    if (!d || typeof d.t !== 'string') return;
    const now = Date.now();
    switch (d.t) {
      case 'chat': {
        if (now - (ws.lc || 0) < 600) return; ws.lc = now;
        const m = clean(d.m, 80).trim(); if (!m) return;
        const e = { n: clean(d.n, 20) || ws.name, m }; history.push(e); if (history.length > 60) history.shift();
        all(Object.assign({ t: 'chat' }, e)); break; }
      case 'pos': {
        if (now - ws.last < 45) return; ws.last = now;
        const p = { t: 'pos', id: ws.id, n: clean(d.n, 20) || ws.name, m: clean(d.m, 30), x: +d.x || 0, y: +d.y || 0, fx: +d.fx || 0, fy: +d.fy || 0, mv: d.mv ? 1 : 0 };
        if (d.a && typeof d.a === 'object') { p.a = {}; for (const k of ['race', 'skin', 'hair', 'body', 'eye', 'hs', 'os']) p.a[k] = d.a[k] | 0; }
        if (d.tf && typeof d.tf === 'object' && JSON.stringify(d.tf).length < 400) p.tf = d.tf;
        for (const k of ['sf', 'pv', 'hp']) if (d[k] != null) p[k] = +d[k] || 0;
        ws.pos = p; all(p, ws); break; }
      case 'score': {
        const e = d.e || {}; if (now - (ws.ls || 0) < 3000) return; ws.ls = now;
        const r = { n: clean(e.n, 20) || ws.name, l: clean(e.l, 20), w: Math.max(0, Math.min(999, e.w | 0)), t: Math.max(0, Math.min(86400, e.t | 0)), win: e.win ? 1 : 0 };
        db.board.push(r); sortBoard(); persist(); all({ t: 'board', board: db.board }); break; }
      case 'q': {
        unqueue(ws); endDuel(ws, false); const c = clean(d.c, 20);
        const i = queue.findIndex(o => o !== ws && o.qc === c && o.readyState === 1);
        const me = { n: clean(d.n, 20) || ws.name, a: d.a && typeof d.a === 'object' ? d.a : {} };
        if (i < 0) { ws.qc = c; ws.me = me; queue.push(ws); break; }
        const o = queue.splice(i, 1)[0]; ws.foe = o; o.foe = ws; ws.ended = o.ended = 0;
        send(o, { t: 'match', side: 0, opp: me }); send(ws, { t: 'match', side: 1, opp: o.me }); break; }
      case 'qc': unqueue(ws); break;
      case 'dp': if (ws.foe) send(ws.foe, { t: 'dp', x: +d.x || 0, y: +d.y || 0, fx: +d.fx || 0, fy: +d.fy || 0, mv: d.mv ? 1 : 0, hp: +d.hp || 0, mx: +d.mx || 1 }); break;
      case 'dh': if (ws.foe) send(ws.foe, { t: 'dh', f: Math.max(0, Math.min(.6, +d.f || 0)), kx: +d.kx || 0, ky: +d.ky || 0 }); break;
      case 'dd': if (ws.foe && !ws.ended) { ws.ended = ws.foe.ended = 1; send(ws.foe, { t: 'dd' }); } break;
      case 'de': unqueue(ws); endDuel(ws, !ws.ended); ws.ended = 0; break;
      case 'ph': {
        const f = Math.max(0, Math.min(.6, +d.f || 0)); if (!f) return;
        for (const c of clients) if (c.id === (d.to | 0) && c !== ws) { send(c, { t: 'ph', f, kx: +d.kx || 0, ky: +d.ky || 0 }); break; }
        break; }
    }
  });

  ws.on('close', () => { clients.delete(ws); unqueue(ws); endDuel(ws, !ws.ended); all({ t: 'bye', id: ws.id }); all({ t: 'online', n: clients.size }); });
  ws.on('error', () => {});
});

/* Render coupe les connexions inactives : ping toutes les 30 s */
setInterval(() => { for (const w of clients) { if (!w.alive) { w.terminate(); continue; } w.alive = false; try { w.ping(); } catch (e) {} } }, 30000);
setInterval(() => { const now = Date.now(); for (const t in db.sessions) if (db.sessions[t].exp < now) delete db.sessions[t]; }, 3600000);

server.listen(PORT, () => console.log('ERA serveur sur le port ' + PORT));
