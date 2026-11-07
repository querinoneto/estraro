/*
 * Portal da Diretoria — emissor de credenciais (JWT) para a sala de áudio e vídeo do JaaS (8x8).
 *
 * Roda gratuitamente no Cloudflare Workers. Para cada pedido:
 *  1. confere o login da pessoa no Firebase (token de identidade, assinatura verificada aqui);
 *  2. confere, no Firestore e COM A PRÓPRIA CREDENCIAL DA PESSOA, se ela tem acesso aprovado ao portal
 *     (as regras do Firestore só deixam ler o diretório "people" e as sessões quem foi aprovado);
 *  3. confere se a sessão existe e está ao vivo;
 *  4. assina a credencial do JaaS com a chave privada, que fica só aqui (segredo do Cloudflare).
 *
 * Variáveis (Settings → Variables and Secrets):
 *   JAAS_APP_ID          ex.: vpaas-magic-cookie-0123456789abcdef   (texto)
 *   JAAS_KEY_ID          ex.: vpaas-magic-cookie-0123456789abcdef/a1b2c3   (texto; "Key ID" completo do JaaS)
 *   JAAS_PRIVATE_KEY     chave privada em PEM ("-----BEGIN PRIVATE KEY-----...")   (SEGREDO)
 *   FIREBASE_PROJECT_ID  bel-estraro   (texto)
 *   ADMIN_EMAILS         querino.neto@gmail.com   (texto; vários separados por vírgula)
 *   ALLOWED_ORIGINS      endereço(s) onde o portal está publicado, ex.: https://querinoneto.github.io   (texto)
 */

const GOOGLE_JWKS = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
let jwksCache = null, jwksUntil = 0;

const enc = new TextEncoder();
const b64url = (bytes) => {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const b64urlJson = (o) => b64url(enc.encode(JSON.stringify(o)));
const fromB64url = (s) => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const r = atob(s), u = new Uint8Array(r.length);
  for (let i = 0; i < r.length; i++) u[i] = r.charCodeAt(i);
  return u;
};
const parseJson = (bytes) => JSON.parse(new TextDecoder().decode(bytes));

/* aceita "https://site.com", "https://site.com/" ou até "https://site.com/pasta": vale o domínio */
const allowedOrigins = (env) => String(env.ALLOWED_ORIGINS || '').split(',').map((x) => x.trim()).filter(Boolean)
  .map((x) => { try { return new URL(x).origin; } catch (e) { return x.replace(/\/$/, ''); } });

function corsHeaders(req, env) {
  const origin = req.headers.get('Origin') || '';
  const allowed = allowedOrigins(env);
  const ok = !allowed.length || allowed.includes(origin);
  return {
    'Access-Control-Allow-Origin': ok ? (origin || '*') : 'null',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}
const reply = (req, env, status, body) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...corsHeaders(req, env) } });

async function googleKeys(fetchFn) {
  if (jwksCache && Date.now() < jwksUntil) return jwksCache;
  const r = await fetchFn(GOOGLE_JWKS);
  if (!r.ok) throw new Error('jwks');
  const j = await r.json();
  const m = /max-age=(\d+)/.exec(r.headers.get('Cache-Control') || '');
  jwksCache = j.keys || [];
  jwksUntil = Date.now() + (m ? +m[1] * 1000 : 3600 * 1000);
  return jwksCache;
}

/* Verifica o token de identidade do Firebase (RS256, emissor e público do projeto, validade, e-mail confirmado). */
async function verifyFirebase(idToken, env, fetchFn) {
  const parts = String(idToken || '').split('.');
  if (parts.length !== 3) throw new Error('token');
  const head = parseJson(fromB64url(parts[0])), body = parseJson(fromB64url(parts[1]));
  if (head.alg !== 'RS256' || !head.kid) throw new Error('token');
  const jwk = (await googleKeys(fetchFn)).find((k) => k.kid === head.kid);
  if (!jwk) throw new Error('token');
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, fromB64url(parts[2]), enc.encode(parts[0] + '.' + parts[1]));
  const now = Math.floor(Date.now() / 1000), pid = env.FIREBASE_PROJECT_ID;
  if (!ok || body.aud !== pid || body.iss !== 'https://securetoken.google.com/' + pid || !body.sub
    || body.exp < now - 60 || body.iat > now + 300) throw new Error('token');
  if (body.email_verified !== true) throw new Error('email');
  return body;
}

/* Lê um documento do Firestore usando a credencial da própria pessoa: as regras decidem se ela pode ler. */
async function readDoc(path, idToken, env, fetchFn) {
  const url = `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/${path}`;
  const r = await fetchFn(url, { headers: { Authorization: 'Bearer ' + idToken } });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error('forbidden');
  return (await r.json()).fields || {};
}
const str = (f) => (f && typeof f.stringValue === 'string' ? f.stringValue : '');
const mapStr = (f, k) => (f && f.mapValue && f.mapValue.fields ? str(f.mapValue.fields[k]) : '');

/* Aceita a chave nos dois formatos usuais: "BEGIN PRIVATE KEY" (PKCS#8) e "BEGIN RSA PRIVATE KEY" (PKCS#1). */
const derLen = (n) => (n < 128 ? [n] : n < 256 ? [0x81, n] : n < 65536 ? [0x82, n >> 8, n & 255] : [0x83, n >> 16, (n >> 8) & 255, n & 255]);
const der = (tag, bytes) => Uint8Array.from([tag, ...derLen(bytes.length), ...bytes]);
function pkcs1to8(p1) {
  const algId = Uint8Array.from([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]);
  return der(0x30, [...Uint8Array.from([0x02, 0x01, 0x00]), ...algId, ...der(0x04, p1)]);
}
async function privateKey(pem) {
  const txt = String(pem || '').replace(/\\n/g, '\n');
  const b = txt.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  if (!b) throw new Error('nokey');
  let raw = Uint8Array.from(atob(b), (c) => c.charCodeAt(0));
  if (/BEGIN RSA PRIVATE KEY/.test(txt)) raw = pkcs1to8(raw);
  return crypto.subtle.importKey('pkcs8', raw, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
}

/* Credencial do JaaS, válida por até 4 horas e só para salas da conta da Liga (room "*").
   Só é emitida para quem tem acesso aprovado e para uma sessão que está ao vivo. */
async function jaasToken({ uid, name, email, moderator }, env) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', kid: env.JAAS_KEY_ID, typ: 'JWT' };
  const payload = {
    aud: 'jitsi', iss: 'chat', sub: env.JAAS_APP_ID, room: '*',
    iat: now, nbf: now - 10, exp: now + 4 * 3600,
    context: {
      user: { id: uid, name, email, moderator: !!moderator, 'hidden-from-recorder': false },
      features: { livestreaming: false, recording: false, transcription: false, 'outbound-call': false, 'sip-outbound-call': false },
    },
  };
  const data = b64urlJson(header) + '.' + b64urlJson(payload);
  const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', await privateKey(env.JAAS_PRIVATE_KEY), enc.encode(data)));
  return data + '.' + b64url(sig);
}

export async function handle(req, env, fetchFn = fetch) {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(req, env) });
  if (req.method !== 'POST') return reply(req, env, 405, { error: 'Use POST.' });
  for (const k of ['JAAS_APP_ID', 'JAAS_KEY_ID', 'JAAS_PRIVATE_KEY', 'FIREBASE_PROJECT_ID'])
    if (!env[k]) return reply(req, env, 500, { error: `Configuração incompleta: falta ${k}.` });
  const allowed = allowedOrigins(env);
  if (allowed.length && !allowed.includes(req.headers.get('Origin') || '')) return reply(req, env, 403, { error: 'Origem não autorizada.' });

  const idToken = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  let body = {};
  try { body = await req.json(); } catch (e) { /* corpo vazio */ }
  const sessionId = String(body.session || '');
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(sessionId)) return reply(req, env, 400, { error: 'Sessão inválida.' });

  let user;
  try { user = await verifyFirebase(idToken, env, fetchFn); }
  catch (e) { return reply(req, env, 401, { error: e.message === 'email' ? 'Confirme seu e-mail primeiro.' : 'Login inválido ou expirado.' }); }

  let person, sess;
  try {
    person = await readDoc('people/' + user.sub, idToken, env, fetchFn);
    sess = await readDoc('sessions/' + sessionId, idToken, env, fetchFn);
  } catch (e) { return reply(req, env, 403, { error: 'Sem acesso aprovado ao portal.' }); }
  if (!person) return reply(req, env, 403, { error: 'Sem acesso aprovado ao portal.' });
  if (!sess) return reply(req, env, 404, { error: 'Sessão não encontrada.' });
  if (str(sess.status) !== 'live') return reply(req, env, 409, { error: 'A sessão não está aberta.' });

  const email = String(user.email || '').toLowerCase();
  const admins = String(env.ADMIN_EMAILS || '').split(',').map((x) => x.trim().toLowerCase()).filter(Boolean);
  const moderator = admins.includes(email) || mapStr(sess.chair, 'uid') === user.sub || mapStr(sess.by, 'uid') === user.sub;
  const role = str(person.role), name = (str(person.name) || email.split('@')[0]) + (role ? ` (${role})` : '');
  const room = 'estraro-' + sessionId.toLowerCase();
  try {
    const jwt = await jaasToken({ uid: user.sub, name, email, moderator }, env);
    return reply(req, env, 200, { jwt, room: env.JAAS_APP_ID + '/' + room, appId: env.JAAS_APP_ID, moderator, name });
  } catch (e) {
    return reply(req, env, 500, { error: 'Não foi possível assinar a credencial (confira JAAS_PRIVATE_KEY).' });
  }
}

export default { fetch: (req, env) => handle(req, env) };
