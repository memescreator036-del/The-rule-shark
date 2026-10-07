'use strict';
// TRS Food backend: zero dependencies, needs Node 18+. Run: node server.js
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = +process.env.PORT || 3000, DIR = __dirname, DBF = path.join(DIR, 'data.json');
const rnd = n => crypto.randomBytes(n).toString('hex');
const hashPw = (p, salt = rnd(16)) => salt + ':' + crypto.scryptSync(p, salt, 64).toString('hex');
const same = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const checkPw = (p, h) => { if (!h) return false; const [s, x] = h.split(':'); return same(x, crypto.scryptSync(p, s, 64).toString('hex')); };
const E = (c, m) => Object.assign(new Error(m), { c });
const str = (v, n = 200) => String(v == null ? '' : v).slice(0, n);

let db;
function save() { const t = DBF + '.tmp'; fs.writeFileSync(t, JSON.stringify(db)); fs.renameSync(t, DBF); }
try { db = JSON.parse(fs.readFileSync(DBF, 'utf8')); }
catch (e) {
  const seed = JSON.parse(fs.readFileSync(path.join(DIR, 'seed.json'), 'utf8'));
  db = { secret: rnd(32), adminHash: hashPw(process.env.ADMIN_PASSCODE || 'admin123'), users: [], orders: [], ...seed };
  save();
}

// Signed tokens (HMAC). r = role, e = subject, x = expiry
const mac = p => crypto.createHmac('sha256', db.secret).update(p).digest('base64url');
const sign = (r, e, days) => { const p = Buffer.from(JSON.stringify({ r, e, x: Date.now() + days * 864e5 })).toString('base64url'); return p + '.' + mac(p); };
const verify = (t, r) => { try { const [p, s] = t.split('.'); if (!same(s, mac(p))) return null; const o = JSON.parse(Buffer.from(p, 'base64url')); return o.r === r && o.x > Date.now() ? o : null; } catch (e) { return null; } };
const bearer = req => (req.headers.authorization || '').slice(7);
const authUser = req => { const o = verify(bearer(req), 'u'), u = o && db.users.find(x => x.e === o.e); if (!u) throw E(401, 'Please log in'); return u; };
const authAdmin = req => { const o = verify(bearer(req), 'a'); if (!o || o.e !== db.adminHash.slice(-12)) throw E(401, 'Admin login required'); };

const fails = new Map();
const guard = ip => { const f = (fails.get(ip) || []).filter(t => Date.now() - t < 9e5); fails.set(ip, f); if (f.length >= 10) throw E(429, 'Too many attempts. Try again in 15 minutes.'); };
const bad = (ip, c, m) => { fails.get(ip).push(Date.now()); throw E(c, m); };

function readBody(req) {
  return new Promise((ok, no) => {
    let n = 0; const b = [];
    req.on('data', c => { n += c.length; if (n > 8e6) { no(E(413, 'Request too large')); req.destroy(); } else b.push(c); });
    req.on('end', () => { try { ok(b.length ? JSON.parse(Buffer.concat(b)) : {}); } catch (e) { no(E(400, 'Invalid JSON')); } });
  });
}

function cleanState(b) {
  const out = {}, hhmm = /^\d\d:\d\d$/;
  if (Array.isArray(b.meals)) out.meals = b.meals.slice(0, 500).map(m => ({
    id: str(m.id, 60) || 'm' + rnd(4), n: str(m.n, 80), d: str(m.d), p: Math.max(0, +m.p || 0), c: str(m.c, 40), e: str(m.e, 8),
    f: m.f ? 1 : 0, s: m.s ? 1 : 0,
    ...(typeof m.img === 'string' && /^data:image\/(jpeg|png|webp);base64,/.test(m.img) && m.img.length < 7e5 ? { img: m.img } : {})
  }));
  if (Array.isArray(b.news)) out.news = b.news.slice(0, 200).map(n => ({ id: +n.id || Date.now(), t: str(n.t, 120), b: str(n.b, 3000), p: n.p ? 1 : 0 }));
  if (Array.isArray(b.offers)) out.offers = b.offers.slice(0, 12).map(o => ({ t: str(o.t, 80), d: str(o.d) }));
  if (b.cfg && typeof b.cfg === 'object') {
    const c = b.cfg, z = {};
    for (const [k, v] of Object.entries(c.z || {}).slice(0, 20)) z[str(k, 40)] = Math.max(0, +v || 0);
    out.cfg = {
      name: str(c.name, 60) || 'Restaurant', tag: str(c.tag, 80), sub: str(c.sub), phone: str(c.phone, 30),
      tel: str(c.tel, 20).replace(/[^\d+]/g, ''), wa: str(c.wa, 20).replace(/\D/g, ''), addr: str(c.addr, 160),
      fo: Math.max(0, +c.fo || 0), pc: str(c.pc, 20).toUpperCase(), pp: Math.min(100, Math.max(0, +c.pp || 0)),
      z: Object.keys(z).length ? z : { 'Pick up': 0 },
      hr: Array.isArray(c.hr) && c.hr.length === 7 ? c.hr.map(h => Array.isArray(h) && hhmm.test(h[0]) && hhmm.test(h[1]) ? [h[0], h[1]] : null) : db.cfg.hr
    };
  }
  return out;
}

// Prices are always recomputed here. The browser's totals are never trusted.
function price(items, promo, zone) {
  if (!Array.isArray(items) || !items.length) throw E(400, 'Cart is empty');
  const c = db.cfg; let sub = 0; const out = [];
  for (const it of items.slice(0, 60)) {
    const m = db.meals.find(x => x.id === it.id), q = Math.max(1, Math.min(50, +it.q | 0));
    if (!m) throw E(400, 'An item is no longer on the menu');
    if (m.s) throw E(400, m.n + ' is sold out');
    sub += m.p * q; out.push({ n: m.n, q });
  }
  if (!(zone in c.z)) throw E(400, 'Choose a delivery zone');
  const disc = promo && c.pc && String(promo).toUpperCase() === c.pc ? sub * c.pp / 100 : 0;
  const fee = sub >= c.fo ? 0 : c.z[zone];
  return { items: out, tot: Math.round((sub - disc + fee) * 100) / 100 };
}

const json = (res, d, c = 200) => { res.writeHead(c, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(d)); };

http.createServer(async (req, res) => {
  try {
    const p = new URL(req.url, 'http://x').pathname, m = req.method, ip = req.socket.remoteAddress;
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'same-origin'); res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    if (!p.startsWith('/api/')) {
      if (m !== 'GET' && m !== 'HEAD') throw E(405, 'Method not allowed');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
      return res.end(fs.readFileSync(path.join(DIR, 'index.html')));
    }
    const b = m === 'GET' ? {} : await readBody(req);
    if (m === 'GET' && p === '/api/state') return json(res, { meals: db.meals, news: db.news, offers: db.offers, cfg: db.cfg, reviews: db.reviews.slice(0, 100) });
    if (m === 'POST' && p === '/api/register') {
      const e = str(b.e, 120).trim().toLowerCase(), n = str(b.n, 60).trim();
      if (!n || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e) || str(b.p, 200).length < 6) throw E(400, 'Enter a name, a valid email and a password of 6+ characters');
      if (db.users.some(u => u.e === e)) throw E(409, 'Email already registered');
      db.users.push({ n, e, h: hashPw(String(b.p)) }); save();
      return json(res, { token: sign('u', e, 30), user: { n, e } }, 201);
    }
    if (m === 'POST' && p === '/api/login') {
      guard(ip); const e = str(b.e, 120).trim().toLowerCase(), u = db.users.find(x => x.e === e);
      if (!u || !checkPw(String(b.p || ''), u.h)) bad(ip, 401, 'Wrong email or password');
      return json(res, { token: sign('u', e, 30), user: { n: u.n, e } });
    }
    if (m === 'GET' && p === '/api/me') { const u = authUser(req); return json(res, { n: u.n, e: u.e }); }
    if (m === 'GET' && p === '/api/orders') { const u = authUser(req); return json(res, db.orders.filter(o => o.u === u.e).sort((a, c) => c.t0 - a.t0)); }
    if (m === 'POST' && p === '/api/orders') {
      const u = authUser(req), pr = price(b.items, b.promo, b.zone), addr = str(b.addr, 300).trim();
      if (!addr) throw E(400, 'Enter a delivery address');
      let id; do id = 'RS' + (1000 + crypto.randomInt(9000)); while (db.orders.some(o => o.id === id));
      // Card payments are NOT processed here. Add your payment provider (e.g. Stripe) before charging real cards.
      const o = { id, u: u.e, nm: str(b.nm || u.n, 60), ph: str(b.ph, 30), items: pr.items, t0: Date.now(), tot: pr.tot, addr, zone: b.zone, pay: b.pay === 'cash' ? 'cash' : 'card', st: 0 };
      db.orders.push(o); save(); return json(res, o, 201);
    }
    if (m === 'POST' && p === '/api/reviews') {
      const u = authUser(req), meal = db.meals.find(x => x.id === b.m), r = Math.round(+b.r), t = str(b.t, 1000).trim();
      if (!meal || !(r >= 1 && r <= 5) || !t) throw E(400, 'Choose a meal, a rating and write a review');
      const rv = { m: meal.id, n: u.n, r, t }; db.reviews.unshift(rv); db.reviews = db.reviews.slice(0, 1000); save(); return json(res, rv, 201);
    }
    if (m === 'POST' && p === '/api/admin/login') {
      guard(ip); if (!checkPw(String(b.passcode || ''), db.adminHash)) bad(ip, 401, 'Wrong passcode');
      return json(res, { token: sign('a', db.adminHash.slice(-12), 1) });
    }
    if (m === 'PUT' && p === '/api/admin/state') {
      authAdmin(req); Object.assign(db, cleanState(b)); let token;
      if (typeof b.np === 'string' && b.np.length >= 4) { db.adminHash = hashPw(b.np); token = sign('a', db.adminHash.slice(-12), 1); }
      save(); return json(res, { ok: 1, token });
    }
    if (m === 'GET' && p === '/api/admin/orders') { authAdmin(req); return json(res, [...db.orders].sort((a, c) => c.t0 - a.t0)); }
    let x;
    if (m === 'PATCH' && (x = p.match(/^\/api\/admin\/orders\/(\w+)$/))) {
      authAdmin(req); const o = db.orders.find(q => q.id === x[1]), st = Math.round(+b.st);
      if (!o || !(st >= 0 && st <= 3)) throw E(400, 'Bad order or status'); o.st = st; save(); return json(res, o);
    }
    throw E(404, 'Not found');
  } catch (e) {
    if (!e.c) console.error(e);
    json(res, { error: e.c ? e.message : 'Server error' }, e.c || 500);
  }
}).listen(PORT, () => console.log('TRS Food running on http://localhost:' + PORT));
