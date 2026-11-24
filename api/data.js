import crypto from 'crypto';

const MAX_AGE = 60 * 60 * 12;
const ACTIONS = ['find', 'index', 'revenue', 'target', 'samples'];
const VERSION = '2026-11-24-samples';

const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const same = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const sign = p => crypto.createHmac('sha256', process.env.SESSION_SECRET).update(p).digest('base64url');
const cookie = (v, age) => 'session=' + v + '; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=' + age;

async function apps(payload) {
  const r = await fetch(process.env.APPS_SCRIPT_URL, {
    method: 'POST',
    redirect: 'follow',
    headers: { 'Content-Type': 'text/plain;charset=utf-8' },
    body: JSON.stringify(Object.assign({ key: process.env.APPS_SCRIPT_KEY }, payload))
  });
  const text = await r.text();
  try { return JSON.parse(text); } catch (e) { throw new Error('Respons backend tidak valid.'); }
}

function makeToken(user) {
  const p = Buffer.from(JSON.stringify({ u: user, exp: Date.now() + MAX_AGE * 1000 })).toString('base64url');
  return p + '.' + sign(p);
}

function readToken(req) {
  const m = String(req.headers.cookie || '').match(/(?:^|;\s*)session=([^;]+)/);
  if (!m) return null;
  const parts = m[1].split('.');
  if (parts.length !== 2 || !same(parts[1], sign(parts[0]))) return null;
  try {
    const d = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    return d.exp > Date.now() ? d : null;
  } catch (e) { return null; }
}

function body(req) {
  if (typeof req.body === 'string') { try { return JSON.parse(req.body); } catch (e) { return {}; } }
  return req.body || {};
}

export default async function handler(req, res) {
  try {
    await handle(req, res);
  } catch (e) {
    console.error(e);
    if (!res.headersSent) res.status(500).json({ error: 'Kesalahan server: ' + (e && e.message ? e.message : e) });
  }
}

async function handle(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const env = process.env;
  const q = req.query || {};
  if (q.action === 'ping') {
    return res.status(200).json({
      version: VERSION,
      actions: ACTIONS,
      configured: { SESSION_SECRET: !!env.SESSION_SECRET, APPS_SCRIPT_URL: !!env.APPS_SCRIPT_URL, APPS_SCRIPT_KEY: !!env.APPS_SCRIPT_KEY }
    });
  }
  const missing = ['SESSION_SECRET', 'APPS_SCRIPT_URL', 'APPS_SCRIPT_KEY'].filter(k => !env[k]);
  if (missing.length) {
    return res.status(500).json({ error: 'Environment variable belum diatur di Vercel: ' + missing.join(', ') });
  }
  const action = q.action || '';

  if (action === 'login') {
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
    const b = body(req), un = String(b.username || '').trim(), pw = String(b.password || '');
    let r = null;
    if (un && pw) {
      try { r = await apps({ action: 'login', username: un, password: pw }); }
      catch (e) { return res.status(502).json({ error: e.message }); }
    }
    if (r && r.error) return res.status(502).json({ error: r.error });
    if (!r || !r.ok) {
      await new Promise(x => setTimeout(x, 800));
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    res.setHeader('Set-Cookie', cookie(makeToken(r.user), MAX_AGE));
    return res.status(200).json({ ok: true, user: r.user });
  }

  if (action === 'logout') {
    res.setHeader('Set-Cookie', cookie('', 0));
    return res.status(200).json({ ok: true });
  }

  const session = readToken(req);
  if (!session) return res.status(401).json({ error: 'Unauthorized' });
  if (ACTIONS.indexOf(action) < 0) return res.status(400).json({ error: 'Unknown action: ' + action });

  const url = new URL(env.APPS_SCRIPT_URL);
  url.searchParams.set('action', action);
  if (action === 'find') url.searchParams.set('q', String(q.q || '').slice(0, 2000));
  url.searchParams.set('key', env.APPS_SCRIPT_KEY);
  url.searchParams.set('user', session.u);
  try {
    const r = await fetch(url, { redirect: 'follow' });
    const text = await r.text();
    let data;
    try { data = JSON.parse(text); } catch (e) { throw new Error('Respons backend tidak valid.'); }
    if (data && data.error === 'Unauthorized') {
      res.setHeader('Set-Cookie', cookie('', 0));
      return res.status(401).json({ error: 'Unauthorized' });
    }
    return res.status(200).json(data);
  } catch (e) {
    return res.status(502).json({ error: e.message || 'Gagal menghubungi backend.' });
  }
}
