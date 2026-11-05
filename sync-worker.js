// ZeroBudget sync — Cloudflare Worker.
// It stores ONE encrypted blob for you. Your budget is encrypted on your devices before it gets here,
// so this script (and Cloudflare) only ever sees scrambled text.
//
// Needs: a KV namespace bound with the variable name  ZB   and a secret named  SYNC_TOKEN.
const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-headers': 'authorization, content-type',
  'access-control-allow-methods': 'GET, PUT, OPTIONS',
  'access-control-max-age': '86400'
};
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json', ...CORS } });

async function sameSecret(a, b) {
  const enc = new TextEncoder();
  const [x, y] = await Promise.all([crypto.subtle.digest('SHA-256', enc.encode(a)), crypto.subtle.digest('SHA-256', enc.encode(b))]);
  const A = new Uint8Array(x), B = new Uint8Array(y);
  let diff = 0;
  for (let i = 0; i < A.length; i++) diff |= A[i] ^ B[i];
  return diff === 0;
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    const url = new URL(req.url);
    if (url.pathname === '/') return new Response('ZeroBudget sync is running.', { headers: CORS });
    if (!env.SYNC_TOKEN || !env.ZB) return json({ error: 'not_configured' }, 500);
    const token = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
    if (!(await sameSecret(token, env.SYNC_TOKEN))) return json({ error: 'unauthorized' }, 401);
    if (url.pathname !== '/v1/state') return json({ error: 'not_found' }, 404);

    const cur = JSON.parse((await env.ZB.get('state')) || '{"rev":0,"blob":null}');
    if (req.method === 'GET') {
      return json(url.searchParams.get('since') === String(cur.rev) ? { rev: cur.rev, unchanged: true } : { rev: cur.rev, blob: cur.blob });
    }
    if (req.method === 'PUT') {
      const text = await req.text();
      if (text.length > 8000000) return json({ error: 'too_large' }, 413);
      let body;
      try { body = JSON.parse(text); } catch (e) { return json({ error: 'bad_json' }, 400); }
      if (body.baseRev !== cur.rev) return json({ error: 'conflict', rev: cur.rev, blob: cur.blob }, 409);
      const next = { rev: cur.rev + 1, blob: body.blob, at: Date.now() };
      await env.ZB.put('state', JSON.stringify(next));
      return json({ rev: next.rev });
    }
    return json({ error: 'method_not_allowed' }, 405);
  }
};
