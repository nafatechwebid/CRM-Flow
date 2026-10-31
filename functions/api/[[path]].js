// BillFlow API: Cloudflare Pages Functions + D1 (database, termasuk foto)
// Binding yang dibutuhkan: DB (D1) dan variabel rahasia SESSION_SECRET.

const COLLECTIONS = ['settings', 'customers', 'products', 'invoices', 'transactions'];
const SESSION_DAYS = 7;
const enc = new TextEncoder();

const json = (obj, status = 200, headers = {}) =>
  new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers } });
const bad = (msg, status = 400) => json({ error: msg }, status);

/* ---------- crypto ---------- */
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64u = (buf) => b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const hex = (buf) => [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (s) => new Uint8Array(s.match(/../g).map((h) => parseInt(h, 16)));

async function hashPassword(password, saltHex) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unhex(saltHex), iterations: 100000 }, key, 256);
  return hex(bits);
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function sign(secret, text) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64u(await crypto.subtle.sign('HMAC', key, enc.encode(text)));
}
async function makeToken(env, email) {
  const body = b64u(enc.encode(JSON.stringify({ e: email, x: Date.now() + SESSION_DAYS * 864e5 })));
  return body + '.' + (await sign(env.SESSION_SECRET, body));
}
async function readSession(env, request) {
  if (!env.SESSION_SECRET) return null;
  const m = /(?:^|;\s*)bf_s=([^;]+)/.exec(request.headers.get('cookie') || '');
  if (!m) return null;
  const [body, sig] = m[1].split('.');
  if (!body || !sig || !safeEqual(sig, await sign(env.SESSION_SECRET, body))) return null;
  try {
    const p = JSON.parse(atob(body.replace(/-/g, '+').replace(/_/g, '/')));
    return p.x > Date.now() ? p.e : null;
  } catch { return null; }
}
const cookie = (value, maxAge) => `bf_s=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;

/* ---------- helpers ---------- */
async function readJson(request) {
  if (!(request.headers.get('content-type') || '').includes('application/json')) throw new Error('Content-Type harus application/json');
  const text = await request.text();
  if (text.length > 6_000_000) throw new Error('Permintaan terlalu besar');
  return JSON.parse(text);
}
const validEmail = (e) => typeof e === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 200;
const validPass = (p) => typeof p === 'string' && p.length >= 8 && p.length <= 200;
async function userCount(env) {
  return (await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first()).n;
}
async function createUser(env, email, password) {
  const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
  await env.DB.prepare('INSERT OR REPLACE INTO users (email, salt, hash) VALUES (?, ?, ?)')
    .bind(email.toLowerCase(), salt, await hashPassword(password, salt)).run();
}
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

/* ---------- router ---------- */
export async function onRequest({ request, env, params }) {
  try {
    if (!env.DB) return bad('Binding DB (D1) belum dipasang di Cloudflare Pages.', 500);
    if (!env.SESSION_SECRET || env.SESSION_SECRET.length < 16) return bad('SESSION_SECRET belum diisi (minimal 16 karakter).', 500);
    const path = '/' + [].concat(params.path || []).join('/');
    const method = request.method;
    const done = (r) => r;

    // ----- publik -----
    if (path === '/me' && method === 'GET') {
      const user = await readSession(env, request);
      return json({ user, setup: (await userCount(env)) === 0 });
    }
    if (path === '/setup' && method === 'POST') {
      if ((await userCount(env)) > 0) return bad('Setup sudah dilakukan.', 403);
      const { email, password } = await readJson(request);
      if (!validEmail(email)) return bad('Email tidak valid.');
      if (!validPass(password)) return bad('Kata sandi minimal 8 karakter.');
      await createUser(env, email, password);
      return json({ user: email.toLowerCase() }, 200, { 'set-cookie': cookie(await makeToken(env, email.toLowerCase()), SESSION_DAYS * 86400) });
    }
    if (path === '/login' && method === 'POST') {
      const { email, password } = await readJson(request);
      const row = validEmail(email) ? await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email.toLowerCase()).first() : null;
      // hitung hash walau user tidak ada, agar waktu respons seragam
      const salt = row ? row.salt : '00'.repeat(16);
      const h = await hashPassword(String(password || ''), salt);
      if (!row || !safeEqual(h, row.hash)) return bad('Email atau kata sandi salah.', 401);
      return json({ user: row.email }, 200, { 'set-cookie': cookie(await makeToken(env, row.email), SESSION_DAYS * 86400) });
    }
    if (path === '/logout' && method === 'POST') {
      return json({ ok: true }, 200, { 'set-cookie': cookie('', 0) });
    }

    // ----- wajib login -----
    const me = await readSession(env, request);
    if (!me) return bad('Belum login.', 401);

    if (path === '/account' && method === 'POST') {
      const { email, password } = await readJson(request);
      if (!validEmail(email)) return bad('Email tidak valid.');
      if (password && !validPass(password)) return bad('Kata sandi minimal 8 karakter.');
      const row = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(me).first();
      if (!row) return bad('Akun tidak ditemukan.', 404);
      const newEmail = email.toLowerCase();
      if (password) await createUser(env, newEmail, password);
      else await env.DB.prepare('UPDATE users SET email = ? WHERE email = ?').bind(newEmail, me).run();
      if (newEmail !== me && password) await env.DB.prepare('DELETE FROM users WHERE email = ?').bind(me).run();
      return json({ user: newEmail }, 200, { 'set-cookie': cookie(await makeToken(env, newEmail), SESSION_DAYS * 86400) });
    }

    if (path === '/data' && method === 'GET') {
      const rows = (await env.DB.prepare('SELECT collection, data FROM docs').all()).results;
      const out = { settings: null, customers: [], products: [], invoices: [], transactions: [] };
      for (const r of rows) {
        const d = JSON.parse(r.data);
        if (r.collection === 'settings') out.settings = d; else if (out[r.collection]) out[r.collection].push(d);
      }
      return json(out);
    }

    if (path === '/sync' && method === 'POST') {
      const { collection, upsert = [], remove = [] } = await readJson(request);
      if (!COLLECTIONS.includes(collection)) return bad('Koleksi tidak dikenal.');
      const now = Date.now();
      const stmts = [];
      for (const doc of upsert) {
        const id = collection === 'settings' ? 'main' : doc && doc.id;
        if (!ID_RE.test(String(id))) return bad('ID tidak valid.');
        if (collection === 'settings') { delete doc.auth; }
        stmts.push(env.DB.prepare('INSERT INTO docs (collection, id, data, updated) VALUES (?, ?, ?, ?) ON CONFLICT(collection, id) DO UPDATE SET data = excluded.data, updated = excluded.updated')
          .bind(collection, String(id), JSON.stringify(doc), now));
      }
      for (const id of remove) {
        if (!ID_RE.test(String(id))) return bad('ID tidak valid.');
        stmts.push(env.DB.prepare('DELETE FROM docs WHERE collection = ? AND id = ?').bind(collection, String(id)));
      }
      for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
      return json({ ok: true, n: stmts.length });
    }

    if (path === '/usage' && method === 'GET') {
      const d1 = (await env.DB.prepare('SELECT COALESCE(SUM(LENGTH(data)), 0) AS b FROM docs').first()).b;
      return json({ d1Bytes: d1 });
    }

    return bad('Endpoint tidak ditemukan.', 404);
  } catch (e) {
    return bad(e && e.message ? e.message : 'Kesalahan server', 400);
  }
}
