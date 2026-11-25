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
const LEAVE_GRACE_MS = 20 * 1000;           // player's last page closed -> logged out after this
const TAB_TIMEOUT_MS = 2 * 60 * 1000;       // no heartbeat from a page this long = that page is gone

// other domains the game talks to (comma separated), e.g. EXTRA_HOSTS=abc.supabase.co,game.example.com
const EXTRA_HOSTS = (process.env.EXTRA_HOSTS || '')
  .split(',')
  .map((h) => h.trim().toLowerCase())
  .filter((h) => /^[a-z0-9.-]+$/.test(h));

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
    if (now - s.created > SESSION_MAX_MS) { endSession(token); continue; }
    const idle = s.sockets.size === 0 && now - s.lastSeen > IDLE_MS;
    if (s.isAdmin) { if (idle) endSession(token); continue; }
    // players: heartbeats from their open pages keep the session alive
    let expired = false;
    for (const [tab, last] of s.tabs) if (now - last > TAB_TIMEOUT_MS) { s.tabs.delete(tab); expired = true; }
    if (s.tabs.size === 0 && !s.emptySince) s.emptySince = now;
    const gone = s.tabs.size === 0 && (expired || now - s.emptySince > LEAVE_GRACE_MS);
    if (gone || idle) endSession(token);
  }
}
setInterval(purge, 5 * 1000);

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

<h3>Debug overlay <small>(admin only, shows on the game pages)</small></h3>
<select id="dbgmode">
<option value="on">Show panel</option>
<option value="min">Button only</option>
<option value="off">Off</option>
</select>

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
    td(tr, s.status + (s.isAdmin ? '' : ' \u00b7 ' + s.tabs + (s.tabs === 1 ? ' page' : ' pages')));
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
(function () {
  var sel = document.getElementById('dbgmode');
  try { sel.value = localStorage.getItem('__dbg') || 'on'; } catch (e) {}
  sel.onchange = function () { try { localStorage.setItem('__dbg', sel.value); } catch (e) {} };
})();
refresh();
setInterval(refresh, 3000);
</script>`);

// ---------- extra hosts + browser shim ----------
// /__x/<host>/... is forwarded to that host (only hosts listed in EXTRA_HOSTS)
const extraHost = (url) => {
  const m = /^\/__x\/([^/?#]*)/.exec(url || '');
  return m ? m[1].toLowerCase() : null;
};

// Runs inside every proxied HTML page (injected into <head>). It:
//  - sends calls to the listed extra hosts through this proxy
//  - admin only: shows the troubleshooting overlay (requests, failures, WebSockets, console errors)
//  - players only: heartbeat so closing the page logs them out
function shimFn(cfg) {
  try {
    var X = cfg.x;
    var isTop = window.top === window;
    var D = !!cfg.dbg && isTop;
    var secure = location.protocol === 'https:';
    var seen = {}, failed = {}, logs = [], socks = [];
    var f = window.fetch;

    function note(o, h) { o[h] = (o[h] || 0) + 1; }
    function two(n) { return (n < 10 ? '0' : '') + n; }
    function add(kind, text, bad) {
      if (!D) return;
      var d = new Date();
      logs.push({ t: two(d.getHours()) + ':' + two(d.getMinutes()) + ':' + two(d.getSeconds()), kind: kind, text: String(text).slice(0, 200), bad: !!bad });
      if (logs.length > 150) logs.shift();
    }
    function isMapped(h) { return /^(www\.)?databallr\.com$/.test(h) || X.indexOf(h.split(':')[0]) > -1; }
    function label(u) {
      try {
        var a = new URL(String(u && u.url ? u.url : u), location.href);
        return a.host === location.host ? 'this site ' + a.pathname.slice(0, 40) : a.host + a.pathname.slice(0, 40);
      } catch (e) { return '?'; }
    }
    function mapUrl(u) {
      try {
        var a = new URL(String(u), location.href);
        if (a.host === location.host) return u;
        if (!/^(https?|wss?):$/.test(a.protocol)) return u;
        note(seen, a.host);
        var ws = a.protocol === 'ws:' || a.protocol === 'wss:';
        var proto = ws ? (secure ? 'wss:' : 'ws:') : location.protocol;
        var rest = a.pathname + a.search + a.hash;
        if (/^(www\.)?databallr\.com$/.test(a.hostname)) return proto + '//' + location.host + rest;
        if (X.indexOf(a.hostname) > -1) return proto + '//' + location.host + '/__x/' + a.hostname + rest;
      } catch (e) {}
      return u;
    }

    if (f) {
      window.fetch = function (input, init) {
        var target = input, orig = label(input), t0 = Date.now();
        var method = String((init && init.method) || (input && input.method) || 'GET').toUpperCase();
        try {
          if (typeof input === 'string' || input instanceof URL) target = mapUrl(input);
          else if (input && input.url) {
            var m = mapUrl(input.url);
            if (m !== input.url) target = new Request(m, input);
          }
        } catch (e) {}
        var p = f.call(this, target, init);
        p.then(function (r) {
          if (!r.ok) note(failed, orig + ' [' + r.status + ']');
          add('fetch', method + ' ' + orig + ' -> ' + r.status + ' ' + (Date.now() - t0) + 'ms', !r.ok);
        }, function (e) {
          note(failed, orig);
          add('fetch', method + ' ' + orig + ' FAILED: ' + ((e && e.message) || e), true);
        });
        return p;
      };
    }

    var xo = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url) {
      var args = Array.prototype.slice.call(arguments);
      var orig = label(url), self = this, mth = String(method).toUpperCase();
      args[1] = mapUrl(url);
      this.addEventListener('loadend', function () {
        var bad = self.status === 0 || self.status >= 400;
        if (bad) note(failed, orig + (self.status ? ' [' + self.status + ']' : ''));
        add('xhr', mth + ' ' + orig + ' -> ' + (self.status || 'FAILED'), bad);
      });
      return xo.apply(this, args);
    };

    var W = window.WebSocket;
    if (W) {
      var WS = function (url, protocols) {
        var orig = label(url), mapped = mapUrl(url);
        var sock = protocols === undefined ? new W(mapped) : new W(mapped, protocols);
        var rec = { url: orig + (mapped !== url ? ' (via proxy)' : ''), state: 'connecting' };
        socks.push(rec);
        if (socks.length > 8) socks.shift();
        add('ws', 'opening ' + rec.url, false);
        sock.addEventListener('open', function () { rec.state = 'open'; add('ws', 'connected ' + rec.url, false); });
        sock.addEventListener('error', function () { rec.state = 'error'; note(failed, orig); add('ws', 'ERROR ' + rec.url, true); });
        sock.addEventListener('close', function (e) {
          rec.state = 'closed ' + e.code;
          add('ws', 'closed ' + e.code + ' ' + rec.url, e.code !== 1000 && e.code !== 1001);
        });
        return sock;
      };
      WS.prototype = W.prototype;
      WS.CONNECTING = 0; WS.OPEN = 1; WS.CLOSING = 2; WS.CLOSED = 3;
      window.WebSocket = WS;
    }

    if (D) {
      ['error', 'warn'].forEach(function (k) {
        var o = console[k];
        console[k] = function () {
          try {
            add('console.' + k, Array.prototype.map.call(arguments, function (a) { return (a && a.message) || String(a); }).join(' '), k === 'error');
          } catch (e) {}
          return o.apply(console, arguments);
        };
      });
      window.addEventListener('error', function (e) { add('error', e.message || 'script/resource error', true); });
      window.addEventListener('unhandledrejection', function (e) { add('promise', (e.reason && e.reason.message) || String(e.reason), true); });

      var mode = function () { try { return localStorage.getItem('__dbg') || 'on'; } catch (e) { return 'on'; } };
      var setMode = function (m) { try { localStorage.setItem('__dbg', m); } catch (e) {} };
      var onlyBad = true;

      var build = function () {
        var wrap = document.createElement('div');
        wrap.style.cssText = 'position:fixed;left:0;bottom:0;z-index:2147483647;font:11px/1.35 ui-monospace,Menlo,monospace;color:#d6ffd6;max-width:100vw;pointer-events:none';
        var panel = document.createElement('div');
        panel.style.cssText = 'background:rgba(0,0,0,.85);padding:6px;max-height:42vh;overflow:auto;width:min(100vw,540px);box-sizing:border-box;pointer-events:auto;border-top-right-radius:8px';
        var bar = document.createElement('div');
        var sum = document.createElement('pre');
        var log = document.createElement('pre');
        sum.style.cssText = log.style.cssText = 'white-space:pre-wrap;word-break:break-all;margin:6px 0 0;font:inherit;color:inherit';
        var btn = document.createElement('button');
        btn.style.cssText = 'pointer-events:auto;font-size:18px;opacity:.7;margin:4px';

        function mk(text, fn) {
          var b = document.createElement('button');
          b.textContent = text;
          b.style.cssText = 'font:inherit;padding:3px 7px;margin:0 4px 0 0';
          b.onclick = fn;
          bar.appendChild(b);
          return b;
        }
        function lines() {
          var sh = Object.keys(seen), fl = Object.keys(failed);
          return [
            'Proxied hosts: ' + (X.length ? X.join(', ') : '(none set)'),
            'Outside hosts: ' + (sh.length ? sh.map(function (h) { return h + ' x' + seen[h] + (isMapped(h) ? ' (proxied)' : ' (NOT proxied)'); }).join(', ') : '(none)'),
            'Failed: ' + (fl.length ? fl.map(function (h) { return h + ' x' + failed[h]; }).join(', ') : '(none)'),
            'WebSockets: ' + (socks.length ? socks.map(function (k) { return k.url + ' [' + k.state + ']'; }).join(' | ') : '(none)')
          ].join('\n');
        }
        function entry(l) { return (l.bad ? '! ' : '  ') + l.t + ' ' + l.kind + ' ' + l.text; }
        function render() {
          var m = mode();
          wrap.style.display = m === 'off' ? 'none' : 'block';
          panel.style.display = m === 'on' ? 'block' : 'none';
          btn.textContent = m === 'on' ? '\u2716' : '\uD83D\uDEE0';
          if (m !== 'on') return;
          filt.textContent = onlyBad ? 'Showing: problems' : 'Showing: all';
          sum.textContent = lines();
          var rows = logs.filter(function (l) { return !onlyBad || l.bad || l.kind === 'ws'; });
          log.textContent = rows.slice(-40).reverse().map(entry).join('\n') || '(nothing yet)';
        }

        var filt = mk('Showing: problems', function () { onlyBad = !onlyBad; render(); });
        mk('Clear', function () { logs.length = 0; seen = {}; failed = {}; render(); });
        mk('Copy', function () {
          var text = lines() + '\n\n' + logs.slice().reverse().map(entry).join('\n');
          function fallback() {
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.style.cssText = 'position:fixed;opacity:0';
            document.body.appendChild(ta);
            ta.select();
            try { document.execCommand('copy'); } catch (e) {}
            document.body.removeChild(ta);
          }
          try { navigator.clipboard.writeText(text).then(null, fallback); } catch (e) { fallback(); }
        });
        mk('Minimize', function () { setMode('min'); render(); });
        mk('Off', function () { setMode('off'); render(); });

        btn.onclick = function () { setMode(mode() === 'on' ? 'min' : 'on'); render(); };
        panel.appendChild(bar);
        panel.appendChild(sum);
        panel.appendChild(log);
        wrap.appendChild(panel);
        wrap.appendChild(btn);
        document.body.appendChild(wrap);
        render();
        setInterval(render, 1000);
      };
      if (document.body) build(); else document.addEventListener('DOMContentLoaded', build);
    }

    if (cfg.hb && isTop) {
      var tab = Math.random().toString(36).slice(2, 10);
      var ping = function () {
        try {
          f.call(window, '/__ping?t=' + tab, { method: 'POST', credentials: 'same-origin', keepalive: true })
            .then(function (r) { if (r.status === 401) location.href = '/__login'; }, function () {});
        } catch (e) {}
      };
      ping();
      setInterval(ping, 8000);
      window.addEventListener('pageshow', ping);
      window.addEventListener('pagehide', function () {
        try { navigator.sendBeacon('/__bye?t=' + tab); } catch (e) {}
      });
    }
  } catch (e) {}
}

const injectShim = (html, session) => {
  const cfg = { x: EXTRA_HOSTS, dbg: !!(session && session.isAdmin), hb: !!(session && !session.isAdmin) };
  const tag = '<script>(' + shimFn.toString() + ')(' + JSON.stringify(cfg) + ');</script>';
  return /<head[^>]*>/i.test(html) ? html.replace(/<head[^>]*>/i, (m) => m + tag) : tag + html;
};

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
      if (TEXTY.test(type)) {
        let out = swap(buffer.toString('utf8'), host);
        if (/text\/html/i.test(type)) out = injectShim(out, getSession(req));
        return out;
      }
      return buffer;
    }),
  },
});

// forwards /__x/<host>/... to an allowed extra host, pretending to be databallr.com
const fixExtraReq = (proxyReq, req) => {
  const h = String(proxyReq.getHeader('host') || '').split(':')[0];
  const c = /(^|\.)databallr\.com$/.test(h) ? stripSid(req.headers.cookie) : '';
  if (c) proxyReq.setHeader('cookie', c);
  else proxyReq.removeHeader('cookie');
  proxyReq.setHeader('origin', TARGET);
  proxyReq.setHeader('referer', TARGET + '/');
};

const extraProxy = createProxyMiddleware({
  router: (req) => 'https://' + extraHost(req.url),
  pathRewrite: (path) => {
    const p = path.replace(/^\/__x\/[^/?#]+/, '');
    return p.startsWith('/') ? p : '/' + p;
  },
  changeOrigin: true,
  ws: false,
  on: {
    proxyReq: fixExtraReq,
    proxyReqWs: fixExtraReq,
    proxyRes: (proxyRes) => {
      ['content-security-policy', 'content-security-policy-report-only', 'x-frame-options', 'strict-transport-security']
        .forEach((h) => delete proxyRes.headers[h]);
      const c = proxyRes.headers['set-cookie'];
      if (c) proxyRes.headers['set-cookie'] = c.map((x) => x.replace(/;\s*domain=[^;]*/i, ''));
    },
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
    tabs: new Map(),                       // open pages -> last heartbeat time
    emptySince: Date.now() + 30 * 1000,    // extra time for the very first page to load
  });
  res.setHeader(
    'Set-Cookie',
    `${SID}=${token}; Path=/; HttpOnly; SameSite=Lax${req.secure ? '; Secure' : ''}`
  );
  res.redirect(303, isAdmin ? '/__admin' : '/');
});

app.post('/__logout', (req, res) => {
  endSession(getCookie(req, SID) || '');
  res.setHeader('Set-Cookie', `${SID}=; Path=/; Max-Age=0`);
  res.redirect(303, '/__login');
});

// page heartbeat: the game page pings every few seconds; 401 tells it to go back to the login page
app.post('/__ping', (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).end();
  if (!s.isAdmin) {
    s.tabs.set(String(req.query.t || 'x').slice(0, 24), Date.now());
    s.emptySince = 0;
  }
  res.status(204).end();
});

// sent by the browser when a page is closed or left
app.post('/__bye', (req, res) => {
  const s = getSession(req);
  if (s && !s.isAdmin) {
    s.tabs.delete(String(req.query.t || 'x').slice(0, 24));
    if (s.tabs.size === 0) s.emptySince = Date.now();
  }
  res.status(204).end();
});

// ---------- admin (only sessions that logged in with the admin credentials) ----------
const requireAdmin = (req, res, next) => {
  const s = getSession(req);
  if (!s || !s.isAdmin) return res.redirect('/__login');
  s.lastSeen = Date.now();
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
    tabs: s.tabs.size,
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

app.use((req, res, next) => {
  const h = extraHost(req.url);
  if (h === null) return next();
  if (!h || !EXTRA_HOSTS.includes(h)) return res.status(404).send('Unknown host');
  extraProxy(req, res, next);
});

app.use(proxy);

const server = app.listen(PORT, '0.0.0.0', () => console.log('proxy up on', PORT));

server.on('upgrade', (req, socket, head) => {
  const s = getSession(req);
  if (!s) {
    socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
    return socket.destroy();
  }
  const x = extraHost(req.url);
  if (x !== null && (!x || !EXTRA_HOSTS.includes(x))) {
    socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
    return socket.destroy();
  }
  s.sockets.add(socket); // lets the admin panel show "playing" and cut the connection on kick
  socket.on('close', () => s.sockets.delete(socket));
  (x === null ? proxy : extraProxy).upgrade(req, socket, head);
});
