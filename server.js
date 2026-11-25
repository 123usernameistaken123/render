const crypto = require('crypto');
const express = require('express');
const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');

const TARGET = 'https://databallr.com';
const PORT = process.env.PORT || 3000;
const TEXTY = /text\/|json|javascript|xml|svg/i;

// ---------- settings (env vars on Render override these defaults) ----------
const ADMIN_USER = (process.env.ADMIN_USER || 'usernameistaken').toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'iambored1';
const ADMIN_NICKNAME = 'user1';

const PLAYER_USER = (process.env.PLAYER_USER || 'user123').toLowerCase();
const PLAYER_PASSWORD = process.env.PLAYER_PASSWORD || 'password123';

const MAX_PLAYERS = parseInt(process.env.MAX_PLAYERS || '10', 10); // admin doesn't count toward this
const IDLE_MS = 20 * 60 * 1000;            // no activity + no live game connection = slot freed
const SESSION_MAX_MS = 12 * 60 * 60 * 1000; // hard limit on any session

const SID = '__psid';

// constant-time string compare
const eq = (a, b) =>
  crypto.timingSafeEqual(
    crypto.createHash('sha256').update(String(a)).digest(),
    crypto.createHash('sha256').update(String(b)).digest()
  );

// ---------- sessions ----------
const sessions = new Map(); // token -> session

const getCookie = (req, name) => {
  const hit = (req.headers.cookie || '').split(/;\s*/).find((p) => p.startsWith(name + '='));
  return hit ? decodeURIComponent(hit.slice(name.length + 1)) : null;
};
const stripSid = (c) =>
  (c || '').split(/;\s*/).filter((p) => p && !p.startsWith(SID + '=')).join('; ');
const getSession = (req) => sessions.get(getCookie(req, SID) || '');

function endSession(token) {
  const s = sessions.get(token);
  if (!s) return;
  s.sockets.forEach((sock) => sock.destroy());
  sessions.delete(token);
}

function purge() {
  const now = Date.now();
  for (const [token, s] of sessions) {
    const tooOld = now - s.created > SESSION_MAX_MS;
    const idle = s.sockets.size === 0 && now - s.lastSeen > IDLE_MS;
    if (tooOld || idle) endSession(token);
  }
}
setInterval(purge, 30 * 1000);

const playerCount = () => [...sessions.values()].filter((s) => !s.isAdmin).length;

// ---------- login rate limit ----------
const attempts = new Map(); // ip -> { n, t }
const tooMany = (ip) => {
  const a = attempts.get(ip);
  return a && Date.now() - a.t < 10 * 60 * 1000 && a.n >= 10;
};
const noteFail = (ip) => {
  const a = attempts.get(ip);
  if (!a || Date.now() - a.t >= 10 * 60 * 1000) attempts.set(ip, { n: 1, t: Date.now() });
  else a.n++;
};

// ---------- pages ----------
const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const page = (title, body) => `<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>
<style>
body{font:16px system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 16px}
input,button{font:inherit;padding:8px;margin:4px 0}
input{width:100%;max-width:320px;box-sizing:border-box}
table{width:100%;border-collapse:collapse;margin-bottom:24px}
td,th{text-align:left;padding:6px;border-bottom:1px solid #ccc}
.err{color:#c00}
</style>${body}`;

const loginPage = (err) =>
  page('Sign in', `<h2>Sign in</h2>${err ? `<p class="err">${esc(err)}</p>` : ''}
<form method="post" action="/__login">
<input name="username" placeholder="Username" autocomplete="username" autocapitalize="none" required><br>
<input name="password" type="password" placeholder="Password" autocomplete="current-password" required><br>
<input name="nickname" placeholder="Nickname (your real name)" maxlength="24" autocomplete="off"><br>
<button>Sign in</button></form>`);

const adminPage = () =>
  page('Admin', `<h2>Admin</h2>
<p><a href="/">Open the game</a> &middot;
<form method="post" action="/__logout" style="display:inline"><button>Log out</button></form></p>

<h3>Online &mdash; players <span id="count">0</span>/<span id="max">${MAX_PLAYERS}</span></h3>
<table><thead><tr><th>Nickname</th><th>Status</th><th>IP</th><th>Signed in</th><th>Last seen</th><th></th></tr></thead>
<tbody id="online"></tbody></table>
<button id="kickall">Kick all players</button>

<script>
async function api(path, body) {
  var r = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body || {}) });
  return r.json().catch(function () { return {}; });
}
function ago(ms) {
  var s = Math.round(ms / 1000);
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm';
  return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
}
function td(tr, text) { var c = document.createElement('td'); c.textContent = text; tr.appendChild(c); return c; }

async function refresh() {
  var res = await fetch('/__admin/data');
  if (!res.ok) return;
  var d = await res.json();
  document.getElementById('count').textContent = d.players;
  document.getElementById('max').textContent = d.max;

  var ob = document.getElementById('online');
  ob.innerHTML = '';
  d.online.forEach(function (s) {
    var tr = document.createElement('tr');
    td(tr, s.nickname + (s.isAdmin ? ' (admin)' : ''));
    td(tr, s.status);
    td(tr, s.ip);
    td(tr, ago(s.signedInFor));
    td(tr, ago(s.idleFor) + ' ago');
    var last = td(tr, '');
    if (!s.isAdmin) {
      var b = document.createElement('button');
      b.textContent = 'Kick';
      b.onclick = async function () { await api('/__admin/kick', { id: s.id }); refresh(); };
      last.appendChild(b);
    }
    ob.appendChild(tr);
  });
}
document.getElementById('kickall').onclick = async function () {
  if (confirm('Kick every player?')) { await api('/__admin/kickall'); refresh(); }
};
refresh();
setInterval(refresh, 3000);
</script>`);

// ---------- proxy ----------
// point any databallr.com URL (links, API calls, ws://) back at this proxy
const swap = (s, host) =>
  s.replace(/((?:https?|wss?):)?\/\/(?:www\.)?databallr\.com/gi, (m, proto) =>
    !proto ? `//${host}` : `${proto.startsWith('ws') ? 'wss:' : 'https:'}//${host}`
  );

const proxy = createProxyMiddleware({
  target: TARGET,
  changeOrigin: true,
  ws: false, // upgrades are handled manually below so they go through the login check
  selfHandleResponse: true,
  on: {
    proxyReq: (proxyReq, req) => {
      const c = stripSid(req.headers.cookie); // never leak our session cookie upstream
      if (c) proxyReq.setHeader('cookie', c);
      else proxyReq.removeHeader('cookie');
      proxyReq.setHeader('referer', TARGET + '/');
      if (proxyReq.getHeader('origin')) proxyReq.setHeader('origin', TARGET);
    },
    proxyReqWs: (proxyReq, req) => {
      const c = stripSid(req.headers.cookie);
      if (c) proxyReq.setHeader('cookie', c);
      else proxyReq.removeHeader('cookie');
      proxyReq.setHeader('origin', TARGET);
    },
    proxyRes: responseInterceptor(async (buffer, proxyRes, req, res) => {
      const host = req.headers.host;
      [
        'content-security-policy',
        'content-security-policy-report-only',
        'x-frame-options',
        'strict-transport-security',
      ].forEach((h) => res.removeHeader(h));

      const loc = res.getHeader('location');
      if (loc) res.setHeader('location', swap(String(loc), host));

      const cookies = res.getHeader('set-cookie');
      if (cookies) {
        res.setHeader('set-cookie', [].concat(cookies).map((c) => c.replace(/;\s*domain=[^;]*/i, '')));
      }

      const type = String(proxyRes.headers['content-type'] || '');
      if (TEXTY.test(type)) return swap(buffer.toString('utf8'), host);
      return buffer;
    }),
  },
});

// ---------- app ----------
const app = express();
app.set('trust proxy', true);

// body parsers are attached per-route only, so proxied POSTs keep their bodies
const form = express.urlencoded({ extended: false, limit: '10kb' });
const json = express.json({ limit: '10kb' });

app.get('/__login', (req, res) => {
  const s = getSession(req);
  if (s) return res.redirect(s.isAdmin ? '/__admin' : '/');
  res.send(loginPage());
});

app.post('/__login', form, (req, res) => {
  const ip = req.ip;
  if (tooMany(ip)) return res.status(429).send(loginPage('Too many attempts. Try again in a few minutes.'));

  const username = String(req.body.username || '').trim().toLowerCase();
  const pw = String(req.body.password || '');
  const nickRaw = String(req.body.nickname || '').trim().replace(/\s+/g, ' ');

  // evaluate everything (no short-circuit) so timing doesn't reveal which part was wrong
  const userIsAdmin = eq(username, ADMIN_USER);
  const passIsAdmin = eq(pw, ADMIN_PASSWORD);
  const userIsPlayer = eq(username, PLAYER_USER);
  const passIsPlayer = eq(pw, PLAYER_PASSWORD);
  const isAdmin = userIsAdmin && passIsAdmin;
  const isPlayer = userIsPlayer && passIsPlayer;

  if (!isAdmin && !isPlayer) {
    noteFail(ip);
    return res.status(401).send(loginPage('Wrong username or password.'));
  }
  attempts.delete(ip);

  // if this browser already had a session, drop it first
  const oldToken = getCookie(req, SID);
  if (oldToken) endSession(oldToken);
  purge();

  let nickname = ADMIN_NICKNAME;
  if (!isAdmin) {
    nickname = nickRaw;
    if (!/^[\p{L}\p{N} ._'-]{1,24}$/u.test(nickname)) {
      return res.status(400).send(loginPage('Enter a nickname (1-24 letters/numbers).'));
    }
    if (nickname.toLowerCase() === ADMIN_NICKNAME.toLowerCase()) {
      return res.status(400).send(loginPage('That nickname is reserved.'));
    }
    const taken = [...sessions.values()].some((s) => s.nickname.toLowerCase() === nickname.toLowerCase());
    if (taken) return res.status(409).send(loginPage('That nickname is already in use.'));
    if (playerCount() >= MAX_PLAYERS) {
      return res.status(503).send(loginPage(`Server is full (${MAX_PLAYERS}/${MAX_PLAYERS}). Try again in a bit.`));
    }
  }

  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, {
    id: crypto.randomBytes(6).toString('hex'), // public id used by the admin panel (not the cookie token)
    token, nickname, isAdmin, ip,
    created: Date.now(), lastSeen: Date.now(), sockets: new Set(),
  });
  res.setHeader(
    'Set-Cookie',
    `${SID}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_MAX_MS / 1000}${req.secure ? '; Secure' : ''}`
  );
  res.redirect(303, isAdmin ? '/__admin' : '/');
});

app.post('/__logout', (req, res) => {
  endSession(getCookie(req, SID) || '');
  res.setHeader('Set-Cookie', `${SID}=; Path=/; Max-Age=0`);
  res.redirect(303, '/__login');
});

// ---------- admin (only sessions that logged in with the admin credentials) ----------
const requireAdmin = (req, res, next) => {
  const s = getSession(req);
  if (!s || !s.isAdmin) return res.redirect('/__login');
  next();
};

app.get('/__admin', requireAdmin, (req, res) => res.send(adminPage()));

app.get('/__admin/data', requireAdmin, (req, res) => {
  purge();
  const now = Date.now();
  const online = [...sessions.values()].map((s) => ({
    id: s.id,
    nickname: s.nickname,
    isAdmin: s.isAdmin,
    ip: s.ip,
    status: s.sockets.size > 0 ? 'playing (live connection)' : now - s.lastSeen < 60000 ? 'browsing' : 'idle',
    signedInFor: now - s.created,
    idleFor: now - s.lastSeen,
  }));
  res.json({ online, players: playerCount(), max: MAX_PLAYERS });
});

app.post('/__admin/kick', requireAdmin, json, (req, res) => {
  const id = String(req.body.id || '');
  for (const [token, s] of sessions) {
    if (!s.isAdmin && s.id === id) endSession(token);
  }
  res.json({ ok: true });
});

app.post('/__admin/kickall', requireAdmin, json, (req, res) => {
  for (const [token, s] of sessions) {
    if (!s.isAdmin) endSession(token);
  }
  res.json({ ok: true });
});

// ---------- everything below requires a valid login ----------
app.use((req, res, next) => {
  const s = getSession(req);
  if (!s) {
    if (req.method === 'GET' && (req.headers.accept || '').includes('text/html')) return res.redirect('/__login');
    return res.status(401).send('Sign in at /__login');
  }
  s.lastSeen = Date.now();
  s.ip = req.ip;
  next();
});

app.use(proxy);

const server = app.listen(PORT, '0.0.0.0', () => console.log('proxy up on', PORT));

server.on('upgrade', (req, socket, head) => {
  const s = getSession(req);
  if (!s) {
    socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
    return socket.destroy();
  }
  s.sockets.add(socket); // lets the admin panel show "playing" and cut the connection on kick
  socket.on('close', () => s.sockets.delete(socket));
  proxy.upgrade(req, socket, head);
});
