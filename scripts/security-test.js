#!/usr/bin/env node
/*
 * Technozion security smoke test  (v3, matched to the real route files)
 * ------------------------------------
 * Run this against the DEPLOYED site after every deploy. Needs only Node 18+ (no npm install).
 *
 *   node smoke-test.js https://YOUR-BACKEND  [https://YOUR-FRONTEND]
 *
 * MODE 1 - anonymous (default). Safe for production: it never creates a user, never logs in as
 * anyone, and never writes data. Every request it sends is one the server is supposed to REJECT.
 * The rate-limit checks use random throwaway email addresses, so no real account can be locked
 * out (about 45 requests hit the login endpoint; the per-IP login limit is 100 per 15 minutes).
 *
 * MODE 2 - authenticated (optional, STAGING ONLY). Enabled by environment variables. It logs in
 * as dedicated TEST accounts and checks what a real logged-in user can and cannot do. Never point
 * this at production and never use real people's accounts.
 *
 *   TZ_USER_A='a@test.example:password'      a normal (non-admin) test user
 *   TZ_ADMIN='admin@test.example:password'   an admin test user (only used as a control)
 *   TZ_JWT_SECRET='...'                      the STAGING jwt_key. Lets the script mint valid tokens
 *                                            to test "role comes from the DB, not the token",
 *                                            expiry, and to validate its own weak-secret check.
 *   TZ_ALLOW_WRITES=1                        allow the admin control call (POST /api/events with an
 *                                            empty body, which validation should reject)
 *   TZ_ALLOW_PUBLIC_TEAM=1                   set if GET /api/events/:id/team is meant to be readable
 *                                            by every logged-in user
 *
 * FAIL = a real security problem. Fix before opening registrations.   (exit code 1)
 * WARN = hardening that is missing, or a check that could not prove anything. Read these too.
 *
 * What a script cannot check is listed at the bottom of the output ("Manual checks").
 */
const crypto = require('crypto');

const API = (process.argv[2] || '').replace(/\/+$/, '');
const WEB = (process.argv[3] || '').replace(/\/+$/, '');
if (!/^https?:\/\//.test(API)) {
  console.error('Usage: node smoke-test.js https://BACKEND [https://FRONTEND]');
  process.exit(2);
}

const ZERO_ID = '000000000000000000000000';
const EVIL_ORIGIN = 'https://evil.example';
const isLocal = (url) => /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/.test(url);
const rand = () => crypto.randomBytes(6).toString('hex');
const randomIp = () => [1, 2, 3, 4].map(() => 1 + Math.floor(Math.random() * 223)).join('.');

// ---------- optional config (authenticated mode) ----------
const env = (k) => (process.env[k] || '').trim();
const parseCred = (v) => {
  const i = v.indexOf(':');
  return i > 0 ? { email: v.slice(0, i), password: v.slice(i + 1) } : null;
};
const CREDS = { A: parseCred(env('TZ_USER_A')), ADMIN: parseCred(env('TZ_ADMIN')) };
const KNOWN_SECRET = env('TZ_JWT_SECRET');
const ALLOW_WRITES = env('TZ_ALLOW_WRITES') === '1';
const PUBLIC_TEAM = env('TZ_ALLOW_PUBLIC_TEAM') === '1';

// ---------- output ----------
const tally = { pass: 0, fail: 0, warn: 0 };
const useColor = process.stdout.isTTY;
const paint = (code, s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const section = (title) => console.log(`\n${paint(1, title)}`);
const note = (msg) => console.log(`  ${paint(36, 'INFO')}  ${msg}`);
function check(severity, name, ok, detail = '', fix = '') {
  if (ok) {
    tally.pass++;
    console.log(`  ${paint(32, 'PASS')}  ${name}`);
    return;
  }
  const isFail = severity === 'critical';
  tally[isFail ? 'fail' : 'warn']++;
  console.log(`  ${isFail ? paint(31, 'FAIL') : paint(33, 'WARN')}  ${name}`);
  if (detail) console.log(`        what we saw: ${detail}`);
  if (fix) console.log(`        fix:         ${fix}`);
}

// ---------- http ----------
async function call(method, path, { headers = {}, json, body, base = API, timeout = 20000 } = {}) {
  const init = { method, headers: { ...headers }, redirect: 'manual', signal: AbortSignal.timeout(timeout) };
  if (json !== undefined) {
    init.headers['content-type'] = 'application/json';
    init.body = JSON.stringify(json);
  } else if (body !== undefined) {
    init.body = body;
  }
  try {
    const res = await fetch(base + path, init);
    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch { /* not JSON */ }
    return { status: res.status, headers: res.headers, text, data };
  } catch (error) {
    return { error: error.message, status: 0, headers: new Headers(), text: '' };
  }
}
const short = (r) => (r.error ? `no response (${r.error})` : `HTTP ${r.status} ${r.text.slice(0, 90).replace(/\s+/g, ' ')}`);
const normBody = (t) => (t || '').replace(/\s+/g, ' ').trim();
const looksHtml = (t) => /^\s*</.test(t || '');

// ---------- token helpers ----------
const b64 = (o) => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');
const algNoneToken = (payload, alg = 'none') => `${b64({ alg, typ: 'JWT' })}.${b64(payload)}.`;
const hs256 = (payload, secret) => {
  const h = b64({ alg: 'HS256', typ: 'JWT' });
  const p = b64(payload);
  const sig = crypto.createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url');
  return `${h}.${p}.${sig}`;
};
const bearer = (t) => ({ authorization: `Bearer ${t}` });
const LEAK = /node_modules|\bat\s+[\w.<>$]+\s+\(|SyntaxError|\/var\/task|\/usr\/src|\/home\/|C:\\\\|MongoServerError|MongooseError|ValidationError/;
const unwrapUser = (res) => res.data?.user ?? res.data?.data ?? res.data ?? {};
const isAdminish = (u) => u?.isAdmin === true || /admin/i.test(JSON.stringify([u?.roles, u?.role]));
const denied = (r) => r.status === 401 || r.status === 403;

// Exposed-file probes. SPA hosts (Vercel etc.) answer 200 + index.html for unknown paths, so a hit
// only counts if the body is NOT html and looks like the real file.
async function probeFiles(base, label) {
  const files = [
    ['/.env', /^[A-Z][A-Z0-9_]*\s*=/m, 'critical'],
    ['/.git/config', /\[core\]/, 'critical'],
    ['/.git/HEAD', /^ref:\s*refs\//m, 'critical'],
    ['/package.json', /"(dependencies|devDependencies|scripts)"/, 'warn'],
  ];
  for (const [path, re, sev] of files) {
    const r = await call('GET', path, { base });
    const leaked = r.status === 200 && !looksHtml(r.text) && re.test(r.text);
    check(sev, `${label}${path} is not publicly readable`, !leaked, short(r),
      'Remove it from the deployed output / web root and ROTATE anything that was inside it.');
  }
}

async function main() {
  console.log(`Backend : ${API}`);
  console.log(`Frontend: ${WEB || '(not given, frontend checks skipped)'}`);
  const authMode = !!(CREDS.A || CREDS.ADMIN);
  console.log(`Mode    : ${authMode ? 'anonymous + authenticated (STAGING ONLY, test accounts)' : 'anonymous (safe for production)'}`);
  if (authMode && !isLocal(API)) note('Authenticated mode is on. Make sure this is STAGING and the accounts are dedicated test accounts.');

  // 0 ------------------------------------------------------------------
  section('0. Backend is reachable');
  const health = await call('GET', '/api/health');
  check('critical', 'GET /api/health answers 200', health.status === 200, short(health),
    'Backend is down or the URL is wrong. Nothing below is meaningful until this passes.');
  if (health.status === 0) {
    console.log('\nStopping: cannot reach the backend.');
    process.exit(1);
  }

  // 1 ------------------------------------------------------------------
  section('1. Tokens: forged, unsigned and weak-secret tokens are rejected');
  // Several id-claim names at once, so the checks do not depend on which one protect() reads.
  const claims = { id: ZERO_ID, _id: ZERO_ID, userId: ZERO_ID, sub: ZERO_ID, roles: 'admin', role: 'admin', isAdmin: true };
  for (const alg of ['none', 'None', 'NONE']) {
    const r = await call('GET', '/api/users/me', { headers: bearer(algNoneToken(claims, alg)) });
    check('critical', `Unsigned token (alg:${alg}) is rejected`, r.status === 401, short(r),
      'Auth middleware accepts unsigned tokens. Pin jwt.verify to { algorithms: ["HS256"] }.');
  }
  const emptySig = await call('GET', '/api/users/me', { headers: bearer(`${b64({ alg: 'HS256', typ: 'JWT' })}.${b64(claims)}.`) });
  check('critical', 'HS256 token with an empty signature is rejected', emptySig.status === 401, short(emptySig));

  const randTok = await call('GET', '/api/users/me', { headers: bearer(hs256(claims, crypto.randomBytes(32))) });
  check('critical', 'Token signed with a random key is rejected', randTok.status === 401, short(randTok));

  // Weak-secret oracle. A token whose signature VERIFIES gets a different answer from the server
  // than a token with a bad signature (typically "user no longer exists" vs "invalid token").
  // So we compare each guess against the random-key baseline instead of matching one message.
  const differs = (r) => r.status !== randTok.status || normBody(r.text) !== normBody(randTok.text);
  const weak = ['secret', 'jwt_key', 'jwt_secret', 'jwtsecret', 'changeme', 'change_me', 'password', '12345678',
    'your_jwt_secret', 'your-secret-key', 'supersecret', 'super_secret', 'technozion', 'technozion2026', 'technozion2025',
    'tz2026', 'tz2025', 'nitw', 'nitwarangal', 'mysecretkey', 'secretkey', 'secret123', 'test', 'dev', 'development',
    'production', 'jwt', 'token', 'key', 'admin', 'qwerty', 'mongodb'];
  let weakHit = null;
  for (const secret of weak) {
    const r = await call('GET', '/api/users/me', { headers: bearer(hs256(claims, secret)) });
    if (r.status === 0 || r.status === 429 || r.status >= 500) continue;
    if (differs(r) || /no longer exists/i.test(r.text) || (r.status >= 200 && r.status < 300)) { weakHit = secret; break; }
  }
  check('critical', 'jwt_key is not a common/guessable secret', !weakHit,
    weakHit ? `a token signed with "${weakHit}" got a different answer from a forged token: the signature verified` : '',
    'Rotate jwt_key to 32+ random bytes: node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))"  (this logs everyone out, which is fine). If you are sure this is a false alarm, the server answers some error text differently per request.');
  if (KNOWN_SECRET) {
    // Control: prove the oracle can actually see a correctly signed token on THIS api.
    const ctl = await call('GET', '/api/users/me', { headers: bearer(hs256(claims, KNOWN_SECRET)) });
    check('warn', 'Control: the weak-secret check can tell a correctly signed token from a forged one', differs(ctl), short(ctl),
      'A correctly signed token looks identical to a forged one, so the "jwt_key is not guessable" PASS above proves nothing. Find which claim protect() reads and add it to `claims`.');
  } else {
    note('Weak-secret check is unvalidated. On STAGING, set TZ_JWT_SECRET=<the real jwt_key> to prove the check can detect a hit.');
  }

  // 2 ------------------------------------------------------------------
  section('2. Registration cannot bypass Google sign-in');
  const victim = { name: 'Attacker', email: `victim-${rand()}@example.com`, password: 'Password123!', registrationType: 'solo' };
  const noTok = await call('POST', '/api/auth/register', { json: victim });
  check('critical', 'Register with no Google token -> 401 GOOGLE_AUTH_REQUIRED',
    noTok.status === 401 && noTok.data?.code === 'GOOGLE_AUTH_REQUIRED', short(noTok),
    'Registration is open without Google verification. Is the googleRegistration middleware on POST /register?');

  const regCases = [
    ['token signed with a random key', hs256({ purpose: 'tz-register', email: victim.email, name: 'x' }, crypto.randomBytes(32))],
    ['unsigned token (alg:none)', algNoneToken({ purpose: 'tz-register', email: victim.email, name: 'x' })],
    ['garbage string', 'not-a-token'],
    ['an object instead of a string', { $ne: null }],
    ['an array instead of a string', ['a', 'b']],
  ];
  for (const [label, tok] of regCases) {
    const r = await call('POST', '/api/auth/register', { json: { ...victim, registrationToken: tok } });
    check('critical', `Register with ${label} -> 401`, r.status === 401, short(r));
  }

  // 3 ------------------------------------------------------------------
  section('3. Google verification endpoint');
  const g1 = await call('POST', '/api/auth/google', { json: {} });
  check('critical', 'No credential -> 400', g1.status === 400, short(g1));
  const g2 = await call('POST', '/api/auth/google', { json: { credential: 'garbage' } });
  const notConfigured = /not configured/i.test(g2.text);
  check('critical', 'Garbage credential is rejected (and server has GOOGLE_CLIENT_ID)', [400, 401].includes(g2.status) && !notConfigured, short(g2),
    notConfigured ? 'GOOGLE_CLIENT_ID is not set on the backend. Set it and redeploy.' : 'Google verification is not rejecting bad tokens.');
  const fakeId = hs256({ iss: 'https://accounts.google.com', aud: 'fake', email: 'a@nitw.ac.in', email_verified: true, exp: 4102444800 }, 'x');
  const g3 = await call('POST', '/api/auth/google', { json: { credential: fakeId } });
  check('critical', 'Self-made fake Google ID token is rejected', [400, 401].includes(g3.status), short(g3));
  const g4 = await call('POST', '/api/auth/google', { json: { credential: { $ne: null } } });
  check('critical', 'Object credential -> 400', g4.status === 400, short(g4));

  // 3b ----------------------------------------------------------------
  section('3b. Upload signing (Cloudinary) needs a verified Google registration token');
  const up0 = await call('POST', '/api/uploads/sign', { json: {} });
  check('critical', 'POST /api/uploads/sign with no token -> 401/403', denied(up0), short(up0),
    'Anyone can mint Cloudinary upload signatures. Is requireGoogleRegistration on POST /api/uploads/sign?');
  for (const [label, tok] of regCases) {
    const r = await call('POST', '/api/uploads/sign', {
      headers: typeof tok === 'string' ? bearer(tok) : {},
      json: { registrationToken: tok },
    });
    check('critical', `POST /api/uploads/sign with ${label} -> 401/403`, denied(r) || r.status === 429, short(r));
  }

  // 4 ------------------------------------------------------------------
  section('4. Login hygiene');
  const l1 = await call('POST', '/api/auth/login', { json: { email: `nobody-${rand()}@example.com`, password: 'wrong-password-123' } });
  check('critical', 'Unknown email -> 400/401 with a generic message',
    [400, 401].includes(l1.status) && !/not found|incorrect password|no user/i.test(l1.text), short(l1),
    'Login reveals whether an email is registered. Use one message: "Invalid email or password".');
  const l2 = await call('POST', '/api/auth/login', { json: { email: { $ne: null }, password: { $ne: null } } });
  check('critical', 'NoSQL operator injection (JSON) -> 400, no token', l2.status === 400 && !/token/i.test(l2.text), short(l2));
  const l3 = await call('POST', '/api/auth/login', {
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'email[$ne]=x&password[$ne]=x',
  });
  check('critical', 'NoSQL operator injection (form-encoded) -> 400, no token', l3.status === 400 && !/token/i.test(l3.text), short(l3));

  // 5 ------------------------------------------------------------------
  section('5. Protected and admin routes reject anonymous and forged callers');
  // These exist in routes/*.js and sit behind protect (plus requireAdmin where noted).
  // A 404 here is a FAIL: it means the path is wrong or the deployed backend is out of date.
  const routes = [
    ['GET', '/api/users/me'],
    ['POST', '/api/users/me/events'],
    ['POST', '/api/events'],                            // protect + requireAdmin
    ['PUT', `/api/events/${ZERO_ID}`],                  // protect + requireAdmin
    ['GET', `/api/events/${ZERO_ID}/registrations`],    // protect + requireAdmin
    ['GET', `/api/events/${ZERO_ID}/team`],             // protect
  ];
  // These are commented out in the code today. They must STAY off (404) or be guarded (401/403).
  // If you re-enable one, move it into `routes` above, and give it an ownership check.
  const offRoutes = [
    ['GET', '/api/users/me/invites'], ['GET', '/api/users/search?q=ab'], ['GET', '/api/users/lookup?email=a@b.com'],
    ['GET', `/api/users/${ZERO_ID}/events`],
    ['POST', `/api/events/${ZERO_ID}/team/invites`], ['POST', `/api/events/${ZERO_ID}/team/invites/accept`],
    ['POST', `/api/events/${ZERO_ID}/team/invites/decline`],
  ];
  const forged = bearer(algNoneToken(claims));
  for (const [method, path] of routes) {
    const a = await call(method, path, { json: method === 'GET' ? undefined : {} });
    const b = await call(method, path, { json: method === 'GET' ? undefined : {}, headers: forged });
    check('critical', `${method} ${path.replace(ZERO_ID, ':id')} rejects anonymous and forged callers`, denied(a) && denied(b),
      `no token: ${a.status}, forged admin token: ${b.status}`,
      a.status === 404 || b.status === 404
        ? 'It answered 404: the path is wrong, or the deployed backend is older than your code. Redeploy and re-run.'
        : 'This route answered an unauthenticated caller. Check that protect / requireAdmin are on it.');
  }
  for (const [method, path] of offRoutes) {
    const a = await call(method, path, { json: method === 'GET' ? undefined : {} });
    const b = await call(method, path, { json: method === 'GET' ? undefined : {}, headers: forged });
    check('critical', `Disabled route stays off: ${method} ${path.replace(ZERO_ID, ':id')}`,
      [401, 403, 404].includes(a.status) && [401, 403, 404].includes(b.status),
      `no token: ${a.status}, forged admin token: ${b.status}`,
      'This route is live again. Re-enabled routes need protect, an ownership check (a user may only see their own data) and a rate limit.');
  }

  section('5b. Public event routes do not leak or crash');
  const list = await call('GET', '/api/events');
  check('critical', 'GET /api/events answers 200 with JSON', list.status === 200 && list.data !== undefined, short(list));
  const SENSITIVE = /"(password|passwordHash|hash|salt|token|secret|googleId|jwt|refreshToken)"\s*:/i;
  check('critical', 'GET /api/events exposes no password/token/secret fields', !SENSITIVE.test(list.text),
    'a sensitive-looking field name appears in the public list', 'Select only public fields in listEvents and strip anything user-related.');
  const emailsInList = [...new Set(list.text.match(/[\w.+-]+@[\w-]+\.[\w.-]+/g) || [])];
  check('warn', 'GET /api/events exposes no email addresses', emailsInList.length === 0,
    `${emailsInList.length} email address(es), e.g. ${emailsInList.slice(0, 2).join(', ')}`,
    'Fine if they are deliberate public contact addresses. If they belong to participants or team members, remove them from the public response.');
  const evList = Array.isArray(list.data) ? list.data : (list.data?.events ?? list.data?.data ?? []);
  const publicEventId = Array.isArray(evList) ? (evList[0]?._id ?? evList[0]?.id ?? null) : null;
  if (publicEventId) {
    const one = await call('GET', `/api/events/${publicEventId}`);
    check('critical', 'GET /api/events/:id answers 200 and exposes no password/token/secret fields', one.status === 200 && !SENSITIVE.test(one.text), short(one));
  } else {
    note('No events returned by GET /api/events, so the single-event and team checks have no id to use. Create one event on staging.');
  }
  const badId = await call('GET', '/api/events/not-a-valid-id');
  check('critical', 'GET /api/events/<invalid id> -> 400/404 without a stack trace', [400, 404].includes(badId.status) && !LEAK.test(badId.text), short(badId),
    'Validate the id (mongoose.isValidObjectId) and return 400/404; never let a CastError or a 500 reach the client.');
  const noEvent = await call('GET', `/api/events/${ZERO_ID}`);
  check('critical', 'GET /api/events/<unknown id> -> 404 without a stack trace', noEvent.status === 404 && !LEAK.test(noEvent.text), short(noEvent));
  const unk = await call('GET', `/api/events?zz_${rand()}=1`);
  check('warn', 'GET /api/events ignores unknown query parameters (query is not used as the database filter)',
    !Array.isArray(evList) || evList.length === 0 || (unk.status === list.status && normBody(unk.text) === normBody(list.text)),
    `plain: ${short(list)} | with an unknown parameter: ${short(unk)}`,
    'listEvents seems to build its Mongo filter from req.query. Whitelist the filter fields and coerce them to strings, or an attacker can inject operators like ?field[$ne]=x.');

  // 6 ------------------------------------------------------------------
  section('6. CORS');
  const preflight = (origin) => call('OPTIONS', '/api/auth/login', {
    headers: { origin, 'access-control-request-method': 'POST', 'access-control-request-headers': 'content-type' },
  });
  const pe = await preflight(EVIL_ORIGIN);
  const acao = pe.headers.get('access-control-allow-origin');
  check('critical', 'A random website origin is NOT allowed', acao !== '*' && acao !== EVIL_ORIGIN,
    `Access-Control-Allow-Origin: ${acao}`,
    'CORS is wide open (CORS_ORIGINS is empty). Set CORS_ORIGINS=https://your-site,https://your-domain on the backend.');
  const pePost = await call('POST', '/api/auth/login', { headers: { origin: EVIL_ORIGIN }, json: { email: `x-${rand()}@example.com`, password: 'wrong-password-123' } });
  const acao2 = pePost.headers.get('access-control-allow-origin');
  check('critical', 'Real requests from a random origin get no CORS permission', acao2 !== '*' && acao2 !== EVIL_ORIGIN, `Access-Control-Allow-Origin: ${acao2}`);
  const peNull = await preflight('null');
  const acaoNull = peNull.headers.get('access-control-allow-origin');
  check('critical', 'Origin "null" (sandboxed iframes, local files) is NOT allowed', acaoNull !== 'null' && acaoNull !== '*', `Access-Control-Allow-Origin: ${acaoNull}`,
    'Do not put "null" in CORS_ORIGINS and do not use a permissive regex.');
  if (WEB) {
    const webUrl = new URL(WEB);
    const webOrigin = webUrl.origin;
    const ok = await preflight(webOrigin);
    check('critical', `Your own frontend (${webOrigin}) IS allowed`, ok.headers.get('access-control-allow-origin') === webOrigin,
      `Access-Control-Allow-Origin: ${ok.headers.get('access-control-allow-origin')}`,
      `Add ${webOrigin} to CORS_ORIGINS, or the site cannot talk to the API.`);
    // Look-alike origins catch sloppy startsWith/endsWith/regex matching.
    const lookalikes = [`${webUrl.protocol}//${webUrl.host}.evil.example`, `${webUrl.protocol}//evil-${webUrl.host}`, `${webUrl.protocol}//${webUrl.hostname}x`];
    for (const o of lookalikes) {
      const r = await preflight(o);
      const v = r.headers.get('access-control-allow-origin');
      check('critical', `Look-alike origin ${o} is NOT allowed`, v !== o && v !== '*', `Access-Control-Allow-Origin: ${v}`,
        'CORS origin matching is a loose startsWith/endsWith/regex check. Compare against an exact allow-list.');
    }
  }

  // 7 ------------------------------------------------------------------
  section('7. Errors do not leak internals; request size is capped');
  check('critical', 'CORS rejection does not show a stack trace', !LEAK.test(pe.text), short(pe),
    'Set NODE_ENV=production on the backend (Express prints stack traces otherwise).');
  const badJson = await call('POST', '/api/auth/login', { headers: { 'content-type': 'application/json' }, body: '{bad json' });
  check('critical', 'Malformed JSON -> 400 without a stack trace', badJson.status === 400 && !LEAK.test(badJson.text), short(badJson),
    'Set NODE_ENV=production on the backend.');
  const nf = await call('GET', `/api/does-not-exist-${rand()}`);
  check('critical', 'Unknown route -> 404 without a stack trace', nf.status === 404 && !LEAK.test(nf.text), short(nf));
  const big = await call('POST', '/api/auth/login', { json: { email: 'a@b.com', password: 'x'.repeat(300 * 1024) } });
  check('warn', 'A 300 KB request body is refused (413)', big.status === 413, short(big),
    'Set an explicit limit: app.use(express.json({ limit: "100kb" })).');

  // 8 ------------------------------------------------------------------
  section('8. Rate limiting (uses throwaway emails only)');
  // One email, 12 attempts. Optionally a different spoofed IP on every attempt.
  async function hammer(spoof) {
    const email = `ratelimit-${rand()}@example.com`;
    const seen = [];
    let firstHeaders = null;
    for (let i = 0; i < 12; i++) {
      const r = await call('POST', '/api/auth/login', {
        json: { email, password: 'wrong-password-123' },
        headers: spoof ? { 'x-forwarded-for': randomIp() } : {},
      });
      if (!firstHeaders) firstHeaders = r.headers;
      seen.push(r.status);
      if (r.status === 429) break;
    }
    return { seen, firstHeaders };
  }
  const plain = await hammer(false);
  check('critical', 'Repeated failed logins for one account get blocked (429)', plain.seen.includes(429),
    `statuses: ${plain.seen.join(' ')}`,
    'Rate limiting is not active. Is the rate-limit patch deployed, and is express-rate-limit installed?');
  const hasHeaders = ['ratelimit', 'ratelimit-policy', 'x-ratelimit-limit'].some((h) => plain.firstHeaders?.get(h));
  check('warn', 'Responses carry RateLimit headers', hasHeaders, 'no RateLimit header seen');
  const rotating = await hammer(true);
  check('critical', 'The per-account limit holds even when the caller rotates IP addresses', rotating.seen.includes(429),
    `statuses: ${rotating.seen.join(' ')}`,
    'An attacker can guess one account\'s password from many IPs. Key the limiter on the account (email) as well as the IP.');

  // The per-IP limit is a different thing: use the RateLimit-Remaining header. Different emails
  // each time, so a per-account limiter cannot be what is counting down.
  const remainingOf = (h) => {
    for (const name of ['ratelimit-remaining', 'x-ratelimit-remaining']) {
      const v = h.get(name);
      if (v !== null && v !== undefined && v !== '' && !Number.isNaN(Number(v))) return Number(v);
    }
    const m = (h.get('ratelimit') || '').match(/remaining=(\d+)/i);
    return m ? Number(m[1]) : null;
  };
  async function remainingSeries(spoof, n = 4) {
    const out = [];
    for (let i = 0; i < n; i++) {
      const r = await call('POST', '/api/auth/login', {
        json: { email: `iplimit-${rand()}@example.com`, password: 'wrong-password-123' },
        headers: spoof ? { 'x-forwarded-for': randomIp() } : {},
      });
      out.push(remainingOf(r.headers));
    }
    return out;
  }
  const baseSeries = await remainingSeries(false);
  const spoofSeries = await remainingSeries(true);
  const counting = baseSeries.every((v) => v !== null) && baseSeries[baseSeries.length - 1] < baseSeries[0];
  if (!counting) {
    check('warn', 'The per-IP limit cannot be dodged by spoofing X-Forwarded-For (header test)', false,
      `RateLimit-Remaining over ${baseSeries.length} requests from different emails: ${baseSeries.join(', ')}`,
      'Inconclusive: no per-IP counter is visible. Verify by hand that TRUST_PROXY equals the REAL number of proxies in front of the app (1 on Vercel), never "true" (see manual check 1).');
  } else {
    const floor = baseSeries[baseSeries.length - 1];
    const spoofable = spoofSeries.some((v) => v !== null && v > floor);
    check('critical', 'The per-IP limit cannot be dodged by spoofing X-Forwarded-For', !spoofable,
      `without spoofing: ${baseSeries.join(', ')}; with a random X-Forwarded-For each time: ${spoofSeries.join(', ')}`,
      'Express trusts client-supplied IPs, so every request gets a fresh limit bucket. TRUST_PROXY must equal the REAL number of proxies in front of the app (1 on Vercel), never "true".');
  }

  // 9 ------------------------------------------------------------------
  section('9. Backend response headers and exposed files (hardening)');
  check('warn', 'X-Powered-By is hidden', !health.headers.get('x-powered-by'), `X-Powered-By: ${health.headers.get('x-powered-by')}`, 'app.disable("x-powered-by") or use helmet.');
  check('warn', 'X-Content-Type-Options: nosniff', /nosniff/i.test(health.headers.get('x-content-type-options') || ''), '', 'npm i helmet; app.use(helmet()).');
  check('warn', 'Auth responses are not cacheable', /no-store/i.test(l1.headers.get('cache-control') || ''), `Cache-Control: ${l1.headers.get('cache-control')}`, 'Send Cache-Control: no-store on /api/auth/*.');
  if (API.startsWith('https://')) {
    check('warn', 'HSTS is sent', !!health.headers.get('strict-transport-security'), '', 'Most hosts add this; otherwise helmet() does.');
  }
  if (!isLocal(API) && API.startsWith('https://')) {
    const http = await call('GET', '/api/health', { base: API.replace(/^https:/, 'http:') });
    check('warn', 'http:// is redirected to https://', [301, 302, 307, 308].includes(http.status) && /^https:/.test(http.headers.get('location') || ''), short(http));
  }
  check('critical', 'Backend is served over HTTPS', API.startsWith('https://') || isLocal(API), API, 'Tokens and passwords must never travel over plain HTTP.');
  await probeFiles(API, 'backend ');
  for (const path of ['/api-docs', '/swagger.json', '/metrics', '/api/debug', '/graphql']) {
    const r = await call('GET', path);
    check('warn', `backend ${path} is not publicly exposed`, !(r.status === 200 && r.text.length > 0), short(r),
      'Docs, metrics and debug endpoints should be off or behind auth in production.');
  }

  // 10 -----------------------------------------------------------------
  if (WEB) {
    section('10. Frontend');
    const page = await call('GET', '/', { base: WEB });
    check('critical', 'Frontend loads', page.status === 200, short(page));
    check('critical', 'Frontend is served over HTTPS', WEB.startsWith('https://') || isLocal(WEB), WEB);
    const h = page.headers;
    const coop = (h.get('cross-origin-opener-policy') || '').toLowerCase();
    check('critical', 'No COOP "same-origin" (it breaks the Google sign-in popup)', coop !== 'same-origin', `Cross-Origin-Opener-Policy: ${coop}`,
      'Use "same-origin-allow-popups" or remove the header.');
    const csp = h.get('content-security-policy') || '';
    check('warn', 'Cannot be framed by other sites (clickjacking)', !!h.get('x-frame-options') || /frame-ancestors/i.test(csp),
      'no X-Frame-Options / frame-ancestors', 'Add X-Frame-Options: DENY in vercel.json headers.');
    check('warn', 'X-Content-Type-Options: nosniff', /nosniff/i.test(h.get('x-content-type-options') || ''));
    check('warn', 'Referrer-Policy is set', !!h.get('referrer-policy'), '', 'strict-origin-when-cross-origin');
    check('warn', 'Content-Security-Policy (or Report-Only) is set', !!csp || !!h.get('content-security-policy-report-only'),
      '', 'Start with Content-Security-Policy-Report-Only. This matters more than it looks: if the login token lives in localStorage, any XSS steals every session.');
    await probeFiles(WEB, 'frontend ');

    // Collect the bundle: scripts from the HTML, plus code-split chunks found inside them.
    const html = page.text;
    const sameOrigin = (s) => !/^(https?:)?\/\//.test(s) || s.startsWith(WEB);
    const toPath = (s) => (s.startsWith(WEB) ? s.slice(WEB.length) : s.startsWith('/') ? s : `/${s}`);
    const queue = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/g)].map((m) => m[1]).filter(sameOrigin).map(toPath);
    const seen = new Set();
    const mainScripts = queue.slice(0, 3);
    const MAX_FILES = 40;
    let bundle = html;
    while (queue.length && seen.size < MAX_FILES) {
      const path = queue.shift().split('?')[0];
      if (seen.has(path)) continue;
      seen.add(path);
      const r = await call('GET', path, { base: WEB, timeout: 30000 });
      bundle += r.text;
      // best-effort chunk discovery (Vite/Rollup "assets/x.js", CRA "static/js/x.chunk.js")
      for (const m of r.text.matchAll(/(?:static\/(?:js|chunks)|assets)\/[\w.@~-]+\.js/g)) queue.push(`/${m[0]}`);
      const runtime = r.text.match(/static\/js\/"\s*\+\s*\w+\s*\+\s*"\."\s*\+\s*(\{[^}]+\})\[\w+\]\s*\+\s*"\.chunk\.js"/);
      if (runtime) {
        for (const m of runtime[1].matchAll(/(\d+|"[^"]+")\s*:\s*"([0-9a-f]{6,})"/g)) queue.push(`/static/js/${m[1].replace(/"/g, '')}.${m[2]}.chunk.js`);
      }
    }
    note(`Scanned ${seen.size} frontend script file(s) for secrets${seen.size >= MAX_FILES ? ' (hit the cap)' : ''}.`);

    const patterns = {
      'Google OAuth client SECRET (GOCSPX-...)': /GOCSPX-[A-Za-z0-9_-]{16,}/,
      'MongoDB connection string with password': /mongodb(\+srv)?:\/\/[^"'\s:@]+:[^"'\s@]+@/,
      'Cloudinary API secret URL': /cloudinary:\/\/\d+:[\w-]+@/,
      'private key': /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
      'api_secret / client_secret assignment': /(?:api|client)_?secret["']?\s*[:=]\s*["'][\w-]{20,}["']/i,
      'AWS access key id': /AKIA[0-9A-Z]{16}/,
      'Stripe live secret key': /sk_live_[0-9a-zA-Z]{20,}/,
      'SendGrid API key': /SG\.[\w-]{16,}\.[\w-]{16,}/,
    };
    for (const [label, re] of Object.entries(patterns)) {
      check('critical', `Public JS bundle does not contain a ${label}`, !re.test(bundle), '',
        'A secret is exposed to every visitor. Remove it from REACT_APP_* / VITE_* variables, ROTATE it, and redeploy.');
    }

    // Source maps hand your original source code to everyone.
    const exposedMaps = [];
    for (const path of mainScripts) {
      const r = await call('GET', `${path.split('?')[0]}.map`, { base: WEB });
      if (r.status === 200 && !looksHtml(r.text) && /"sources"\s*:/.test(r.text)) exposedMaps.push(path);
    }
    check('warn', 'Source maps are not public', exposedMaps.length === 0, exposedMaps.join(', '),
      'Build with GENERATE_SOURCEMAP=false (CRA) or build.sourcemap=false (Vite), or do not deploy the .map files.');

    if (!isLocal(WEB) && WEB.startsWith('https://')) {
      const http = await call('GET', '/', { base: WEB.replace(/^https:/, 'http:') });
      check('warn', 'http:// is redirected to https://', [301, 302, 307, 308].includes(http.status) && /^https:/.test(http.headers.get('location') || ''), short(http));
    }
  }

  // 11 -----------------------------------------------------------------
  if (authMode) {
    section('11. Authenticated checks (STAGING, dedicated test accounts)');
    async function loginAs(label, cred) {
      if (!cred) return null;
      const r = await call('POST', '/api/auth/login', { json: cred });
      const token = r.data?.token ?? r.data?.accessToken ?? r.data?.data?.token;
      if (!token) {
        check('critical', `Test account ${label} can log in`, false, short(r),
          'Check the credentials, and that login answers { token: "..." } (adjust loginAs() if your response shape differs).');
        return null;
      }
      const me = await call('GET', '/api/users/me', { headers: bearer(token) });
      const user = unwrapUser(me);
      const id = user._id ?? user.id;
      check('critical', `Test account ${label}: login works and /api/users/me returns the user`, me.status === 200 && !!id, short(me));
      return id ? { label, token, id, user, cred } : null;
    }
    const A = await loginAs('A', CREDS.A);
    const ADM = await loginAs('ADMIN', CREDS.ADMIN);
    const normalA = A && !isAdminish(A.user) ? A : null;
    if (A && !normalA) check('warn', 'Test account A is a normal (non-admin) user', false, `roles: ${JSON.stringify(A.user.roles ?? A.user.role)}`, 'Use a non-admin account for TZ_USER_A, otherwise the denial checks below prove nothing.');

    // A normal user must not reach admin routes (requireAdmin runs before the handler, so ZERO_ID is fine).
    if (normalA) {
      const adminRoutes = [['POST', '/api/events'], ['PUT', `/api/events/${ZERO_ID}`], ['GET', `/api/events/${ZERO_ID}/registrations`]];
      for (const [m, p] of adminRoutes) {
        const r = await call(m, p, { headers: bearer(normalA.token), json: m === 'GET' ? undefined : {} });
        const label = `Normal user is denied ${m} ${p.replace(ZERO_ID, ':id')}`;
        if (r.status === 404) {
          check('warn', label, false, short(r), '404 means authorization was not actually exercised (path wrong or deployed code older than your repo).');
          continue;
        }
        check('critical', label, denied(r), short(r), 'A normal user reached an admin route (400 means validation ran, so the role check did not stop them). Is requireAdmin on it?');
      }
      if (ADM && ALLOW_WRITES) {
        const r = await call('POST', '/api/events', { headers: bearer(ADM.token), json: {} });
        check('warn', 'Control: the admin account is NOT blocked on POST /api/events (so the denials above mean something)',
          !denied(r) && r.status !== 404, short(r), 'The admin got 401/403/404. Either the admin test account lacks the role or the path changed.');
        if (r.status >= 200 && r.status < 300) note('The admin POST /api/events {} succeeded and may have created an empty event on staging. Delete it.');
      } else if (ADM) {
        note('Admin control call skipped (set TZ_ALLOW_WRITES=1 to allow it).');
      }
    }

    // GET /api/events/:id/team is behind protect only: can any logged-in user read other people's team details?
    if (normalA && publicEventId) {
      const team = await call('GET', `/api/events/${publicEventId}/team`, { headers: bearer(normalA.token) });
      const teamEmails = team.text.match(/[\w.+-]+@[\w-]+\.[\w.-]+/g) || [];
      const leaks = team.status === 200 && teamEmails.length > 0;
      check('critical', "A logged-in user who is not on the team cannot read the team's details (GET /api/events/:id/team)", PUBLIC_TEAM || !leaks,
        `HTTP ${team.status}, ${teamEmails.length} email address(es) in the response`,
        "IDOR: getEventTeam hands other people's details to any logged-in user. Check that req.user is on the team (or an admin) before returning it. If the team list is meant to be visible to everyone, set TZ_ALLOW_PUBLIC_TEAM=1.");
    } else if (normalA) {
      note('Team-visibility check skipped: no public event id available.');
    }

    // Tokens minted with the real (staging) secret: is the role read from the DB, does expiry work?
    if (KNOWN_SECRET && normalA) {
      const now = Math.floor(Date.now() / 1000);
      const idc = { id: normalA.id, _id: normalA.id, userId: normalA.id, sub: normalA.id };
      const fine = await call('GET', '/api/users/me', { headers: bearer(hs256({ ...idc, iat: now, exp: now + 300 }, KNOWN_SECRET)) });
      check('warn', 'Control: a correctly signed token for test user A is accepted', fine.status === 200, short(fine),
        'The server does not accept tokens built from these claims, so the two checks below prove nothing. Find which claim names your jwt.sign() uses and add them to `idc`.');
      const escal = await call('POST', '/api/events', { headers: bearer(hs256({ ...idc, roles: 'admin', role: 'admin', isAdmin: true, iat: now, exp: now + 300 }, KNOWN_SECRET)), json: {} });
      check('critical', 'Role comes from the database, not from claims inside the token', fine.status !== 200 ? false : denied(escal), short(escal),
        'A token that merely CLAIMS admin was treated as admin. Look the user up and read the role server-side on every request.');
      const expired = await call('GET', '/api/users/me', { headers: bearer(hs256({ ...idc, iat: now - 7200, exp: now - 3600 }, KNOWN_SECRET)) });
      check('critical', 'An expired (but correctly signed) token is rejected', fine.status !== 200 ? false : expired.status === 401, short(expired),
        'jwt.verify must not use ignoreExpiration, and tokens must carry an exp claim.');
    } else if (!KNOWN_SECRET) {
      note('Skipped: role-from-token and expiry checks (need TZ_JWT_SECRET = the staging jwt_key).');
    }

    // Login must not reveal which emails exist.
    if (A) {
      const wrong = await call('POST', '/api/auth/login', { json: { email: A.cred.email, password: 'wrong-password-123' } });
      const unknown = await call('POST', '/api/auth/login', { json: { email: `nobody-${rand()}@example.com`, password: 'wrong-password-123' } });
      check('critical', 'Login answers identically for "real email, wrong password" and "no such user"',
        wrong.status === unknown.status && normBody(wrong.text) === normBody(unknown.text),
        `real email: ${short(wrong)} | unknown email: ${short(unknown)}`,
        'Accounts can be enumerated from the login response (status or message differs). Return one identical answer.');
    }
  } else {
    section('11. Authenticated checks');
    note('Skipped. Set TZ_USER_A (and optionally TZ_ADMIN, TZ_JWT_SECRET) on STAGING to test admin-route denial, team-list access, role-from-token, expiry and login enumeration.');
  }

  // summary ------------------------------------------------------------
  console.log(`\n${paint(1, 'Result')}: ${paint(32, tally.pass + ' passed')}, ${paint(31, tally.fail + ' failed')}, ${paint(33, tally.warn + ' warnings')}`);
  console.log(`
Manual checks (a script cannot see these):
  1. Run this script from TWO different networks (e.g. WiFi and phone data) and confirm the
     rate-limit result is the same. If one network's requests use up the other's allowance,
     the proxy setting is wrong and real users will get locked out.
  2. Backend logs must NOT contain ERR_ERL_UNEXPECTED_X_FORWARDED_FOR (rate limiter cannot see real IPs).
  3. Google Cloud Console: the production domain is under "Authorized JavaScript origins".
  4. Cloudinary: the upload preset has a folder, allowed formats, a size limit and overwrite OFF.
     Anyone with a Google account can probably get a registration token and sign uploads, so also
     confirm uploads are capped per account and try a non-image, an oversized file and an odd filename.
  5. Platform: firewall / attack protection ON, spend and usage alerts set, log access for the dev team.
  6. Secrets: nothing in git history (e.g. run gitleaks), and anything that ever leaked has been rotated.
  7. Registration SUCCESS path (needs a real Google sign-in on staging): the email and name must come
     from the verified Google token, not the request body, and roles / role / isAdmin sent in the
     register body must be ignored.
  8. Dependencies: run "npm audit --omit=dev" in the backend and the frontend; fix high/critical.
  9. POST /api/users/me/events (cannot be tested generically): on staging, try extra body fields
     (userId, roles, paid/status flags), event ids that do not exist or are closed/full, the same
     event twice, and a huge list. Whenever you re-enable invites or user search/lookup, each needs
     protect, a rule that a user only sees their own data, and a rate limit.
 10. If the login token is kept in localStorage, treat any XSS as full account takeover: no
     dangerouslySetInnerHTML with user content, and get a real Content-Security-Policy in place.
`);
  process.exit(tally.fail > 0 ? 1 : 0);
}

main().catch((e) => { console.error('Test runner crashed:', e); process.exit(2); });