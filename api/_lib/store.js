// Tiny KV store for vault docs & invite codes.
// Uses Upstash Redis REST when configured; falls back to per-instance memory.
const mem = new Map();

function restCfg() {
  return process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN
    ? { url: process.env.UPSTASH_REDIS_REST_URL, tok: process.env.UPSTASH_REDIS_REST_TOKEN } : null;
}

async function kvGet(key) {
  const c = restCfg();
  if (c) {
    try {
      const r = await fetch(`${c.url}/get/${encodeURIComponent(key)}`, { headers: { Authorization: `Bearer ${c.tok}` } });
      const j = await r.json();
      return j.result ?? null;
    } catch { return null; }
  }
  const e = mem.get(key);
  if (e && e.exp && Date.now() > e.exp) { mem.delete(key); return null; }
  return e ? e.v : null;
}

async function kvSet(key, value, ttlSeconds) {
  const c = restCfg();
  if (c) {
    try {
      const args = ttlSeconds ? ['EX', String(ttlSeconds)] : [];
      await fetch(`${c.url}/set/${encodeURIComponent(key)}/${encodeURIComponent(value)}${args.length ? '?' + args.join('=') : ''}`,
        { headers: { Authorization: `Bearer ${c.tok}` } });
      return;
    } catch { /* fall through to memory */ }
  }
  mem.set(key, { v: value, exp: ttlSeconds ? Date.now() + ttlSeconds * 1000 : null });
}

module.exports = { kvGet, kvSet };
