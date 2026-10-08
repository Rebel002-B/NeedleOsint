const express = require('express');
const session = require('express-session');
const { rateLimit } = require('express-rate-limit');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 8 * 60 * 60 * 1000
  }
}));

function loadPasswordHash() {
  if (process.env.PASSWORD_HASH) return process.env.PASSWORD_HASH;
  const configPath = path.join(__dirname, 'config.json');
  if (fs.existsSync(configPath)) {
    try {
      return JSON.parse(fs.readFileSync(configPath, 'utf8')).passwordHash || null;
    } catch {
      return null;
    }
  }
  return null;
}

let passwordHash = loadPasswordHash();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  handler: (req, res) => {
    res.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.' });
  }
});

function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
  return res.redirect('/login');
}

const store = {
  players: new Map(),
  history: new Map(),
  alerts: new Map()
};

const ROBLOX_API = {
  user: (id) => `https://users.roblox.com/v1/users/${id}`,
  presence: 'https://presence.roblox.com/v1/presence/users',
  thumbnail: (ids) => `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${ids}&size=150x150&format=Png&isCircular=true`,
  game: (placeId) => `https://games.roblox.com/v1/games?placeIds=${placeId}`,
  usernameSearch: 'https://users.roblox.com/v1/usernames/users'
};

const TIMEOUTS = { request: 9000 };

async function robloxGet(url) {
  const resp = await axios.get(url, {
    timeout: TIMEOUTS.request,
    headers: { 'Accept': 'application/json', 'User-Agent': 'NeedleOSINT/2.0' }
  });
  return resp.data;
}

async function robloxPost(url, data) {
  const resp = await axios.post(url, data, {
    timeout: TIMEOUTS.request,
    headers: { 'Accept': 'application/json', 'Content-Type': 'application/json', 'User-Agent': 'NeedleOSINT/2.0' }
  });
  return resp.data;
}

const PATTERN = {
  RAPID_REJOIN_COUNT: 3,
  RAPID_REJOIN_WINDOW_MS: 30 * 60 * 1000,
  FREQ_SWITCH_COUNT: 5,
  FREQ_SWITCH_WINDOW_MS: 60 * 60 * 1000,
  INACTIVITY_DAYS: 7,
  BURST_INACTIVITY_MS: 3 * 24 * 60 * 60 * 1000,
  BURST_COUNT: 5,
  BURST_WINDOW_MS: 3 * 60 * 60 * 1000,
  REPEATED_GAME_RATIO: 0.70
};

function getTransitions(snapshots) {
  const result = [];
  for (let i = 1; i < snapshots.length; i++) {
    const prev = snapshots[i - 1];
    const curr = snapshots[i];
    if (curr.placeId && curr.placeId !== prev.placeId) {
      result.push({
        time: curr.timestamp,
        placeId: curr.placeId,
        gameName: curr.gameName || String(curr.placeId)
      });
    }
  }
  return result;
}

function detectPatterns(userId) {
  const snapshots = store.history.get(userId) || [];
  if (snapshots.length < 2) return [];

  const now = Date.now();
  const patterns = [];
  const transitions = getTransitions(snapshots);

  const recentTransitions = transitions.filter(t => now - t.time < PATTERN.RAPID_REJOIN_WINDOW_MS);
  const gameHitMap = {};
  recentTransitions.forEach(t => {
    gameHitMap[t.placeId] = (gameHitMap[t.placeId] || { count: 0, name: t.gameName });
    gameHitMap[t.placeId].count++;
  });
  Object.values(gameHitMap).forEach(g => {
    if (g.count >= PATTERN.RAPID_REJOIN_COUNT) {
      patterns.push({
        type: 'RAPID_REJOIN',
        severity: g.count >= 6 ? 'attention' : 'unusual',
        description: `Joined "${g.name}" ${g.count}x in 30 minutes`,
        count: g.count,
        detail: g.name
      });
    }
  });

  const hourTransitions = transitions.filter(t => now - t.time < PATTERN.FREQ_SWITCH_WINDOW_MS);
  if (hourTransitions.length >= PATTERN.FREQ_SWITCH_COUNT) {
    patterns.push({
      type: 'FREQUENT_SWITCH',
      severity: hourTransitions.length >= 9 ? 'attention' : 'unusual',
      description: `${hourTransitions.length} experience changes in the last hour`,
      count: hourTransitions.length,
      detail: null
    });
  }

  const latest = snapshots[snapshots.length - 1];
  if (latest.presenceType === 0 && latest.lastOnline) {
    const offlineMs = now - new Date(latest.lastOnline).getTime();
    const offlineDays = offlineMs / (1000 * 60 * 60 * 24);
    if (offlineDays >= PATTERN.INACTIVITY_DAYS) {
      patterns.push({
        type: 'LONG_INACTIVITY',
        severity: 'unusual',
        description: `Offline for ${Math.floor(offlineDays)} days`,
        count: Math.floor(offlineDays),
        detail: null
      });
    }
  }

  const prevOfflineSnap = snapshots.slice(0, -1).reverse().find(s => s.presenceType === 0);
  if (prevOfflineSnap) {
    const inactiveMs = (latest.timestamp || now) - prevOfflineSnap.timestamp;
    if (inactiveMs >= PATTERN.BURST_INACTIVITY_MS) {
      const burstTransitions = transitions.filter(t => now - t.time < PATTERN.BURST_WINDOW_MS);
      if (burstTransitions.length >= PATTERN.BURST_COUNT) {
        patterns.push({
          type: 'SUDDEN_BURST',
          severity: 'attention',
          description: `${burstTransitions.length} sessions in 3h after ${Math.floor(inactiveMs / (1000 * 60 * 60 * 24))}d inactivity`,
          count: burstTransitions.length,
          detail: null
        });
      }
    }
  }

  if (transitions.length >= 6) {
    const gameCount = {};
    transitions.forEach(t => { gameCount[t.placeId] = (gameCount[t.placeId] || { n: 0, name: t.gameName }); gameCount[t.placeId].n++; });
    const top = Object.values(gameCount).sort((a, b) => b.n - a.n)[0];
    if (top && top.n / transitions.length >= PATTERN.REPEATED_GAME_RATIO) {
      patterns.push({
        type: 'REPEATED_GAME',
        severity: 'unusual',
        description: `${Math.round(top.n / transitions.length * 100)}% of sessions in "${top.name}"`,
        count: top.n,
        detail: top.name
      });
    }
  }

  return patterns;
}

function upsertAlert(userId, playerName, pattern) {
  const id = `${userId}__${pattern.type}`;
  const existing = store.alerts.get(id);
  if (existing && !existing.resolved) {
    existing.count = pattern.count;
    existing.description = pattern.description;
    existing.lastSeenAt = new Date().toISOString();
    return;
  }
  store.alerts.set(id, {
    id,
    userId,
    playerName,
    type: pattern.type,
    severity: pattern.severity,
    description: pattern.description,
    count: pattern.count,
    detail: pattern.detail || null,
    detectedAt: new Date().toISOString(),
    lastSeenAt: new Date().toISOString(),
    resolved: false,
    resolvedAt: null
  });
}

async function pollPlayers() {
  if (store.players.size === 0) return;
  const userIds = Array.from(store.players.keys());
  try {
    const [presenceResp, thumbResp] = await Promise.all([
      robloxPost(ROBLOX_API.presence, { userIds }),
      robloxGet(ROBLOX_API.thumbnail(userIds.join(',')))
    ]);
    const thumbMap = {};
    (thumbResp?.data || []).forEach(t => { thumbMap[t.targetId] = t.imageUrl; });
    const now = Date.now();
    for (const p of (presenceResp?.userPresences || [])) {
      const uid = p.userId;
      const player = store.players.get(uid);
      if (!player) continue;
      const snap = {
        timestamp: now,
        presenceType: p.userPresenceType,
        lastOnline: p.lastOnline,
        placeId: p.placeId || null,
        rootPlaceId: p.rootPlaceId || null,
        gameId: p.gameId || null,
        gameName: p.lastLocation || null
      };
      if (!store.history.has(uid)) store.history.set(uid, []);
      const hist = store.history.get(uid);
      hist.push(snap);
      const cutoff = now - 48 * 60 * 60 * 1000;
      store.history.set(uid, hist.filter(s => s.timestamp > cutoff));
      player.currentPresence = snap;
      if (thumbMap[uid]) player.avatarUrl = thumbMap[uid];
      const patterns = detectPatterns(uid);
      player.patterns = patterns;
      const statusRank = { attention: 2, unusual: 1, normal: 0 };
      player.status = patterns.reduce((best, p) => statusRank[p.severity] > statusRank[best] ? p.severity : best, 'normal');
      patterns.forEach(pat => upsertAlert(uid, player.username, pat));
    }
  } catch (_) {}
}

setInterval(pollPlayers, 30000);

app.use(express.static(__dirname, {
  index: false,
  dotfiles: 'deny',
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('config.json') || filePath.endsWith('server.js') || filePath.endsWith('.env')) {
      res.status(403).end();
    }
  }
}));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.get('/login', (req, res) => {
  if (req.session?.authenticated) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { password } = req.body || {};
  if (!password || !passwordHash) return res.status(400).json({ error: 'Bad request' });
  try {
    const match = await bcrypt.compare(String(password), passwordHash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Session error' });
      req.session.authenticated = true;
      req.session.loginTime = new Date().toISOString();
      res.json({ ok: true });
    });
  } catch (_) {
    res.status(500).json({ error: 'Authentication error' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/status', (req, res) => {
  res.json({ authenticated: !!(req.session?.authenticated) });
});

app.get('/api/players', requireAuth, (req, res) => {
  const players = Array.from(store.players.values()).map(p => ({
    ...p,
    snapshotCount: (store.history.get(p.userId) || []).length
  }));
  res.json({ players });
});

app.post('/api/players', requireAuth, async (req, res) => {
  const { userId, username } = req.body || {};
  if (!userId && !username) return res.status(400).json({ error: 'Provide userId or username' });
  let uid = userId ? parseInt(userId) : null;
  let uname = username || null;
  try {
    if (!uid && uname) {
      const data = await robloxPost(ROBLOX_API.usernameSearch, { usernames: [uname], excludeBannedUsers: false });
      const found = data?.data?.[0];
      if (!found) return res.status(404).json({ error: 'User not found' });
      uid = found.id;
      uname = found.name;
    }
    if (store.players.has(uid)) return res.status(409).json({ error: 'Already monitored' });
    const info = await robloxGet(ROBLOX_API.user(uid));
    const player = {
      userId: uid,
      username: info.name,
      displayName: info.displayName,
      description: info.description || '',
      created: info.created,
      isBanned: info.isBanned || false,
      addedAt: new Date().toISOString(),
      status: 'normal',
      patterns: [],
      currentPresence: null,
      avatarUrl: null
    };
    store.players.set(uid, player);
    setTimeout(pollPlayers, 500);
    res.json({ ok: true, player });
  } catch (err) {
    const status = err?.response?.status || 500;
    const message = err?.response?.data?.errors?.[0]?.message || 'Failed to add player';
    res.status(status).json({ error: message });
  }
});

app.delete('/api/players/:userId', requireAuth, (req, res) => {
  const uid = parseInt(req.params.userId);
  if (!store.players.has(uid)) return res.status(404).json({ error: 'Not found' });
  store.players.delete(uid);
  store.history.delete(uid);
  for (const [k, a] of store.alerts) {
    if (a.userId === uid) store.alerts.delete(k);
  }
  res.json({ ok: true });
});

app.get('/api/players/:userId', requireAuth, (req, res) => {
  const uid = parseInt(req.params.userId);
  const player = store.players.get(uid);
  if (!player) return res.status(404).json({ error: 'Not found' });
  const history = store.history.get(uid) || [];
  const alerts = Array.from(store.alerts.values()).filter(a => a.userId === uid);
  res.json({ player, history, alerts });
});

app.get('/api/alerts', requireAuth, (req, res) => {
  const alerts = Array.from(store.alerts.values())
    .sort((a, b) => new Date(b.detectedAt) - new Date(a.detectedAt));
  res.json({ alerts });
});

app.patch('/api/alerts/:id', requireAuth, (req, res) => {
  const alert = store.alerts.get(req.params.id);
  if (!alert) return res.status(404).json({ error: 'Not found' });
  alert.resolved = Boolean(req.body.resolved);
  alert.resolvedAt = alert.resolved ? new Date().toISOString() : null;
  res.json({ ok: true, alert });
});

app.get('/api/roblox/user/:userId', requireAuth, async (req, res) => {
  try {
    res.json(await robloxGet(ROBLOX_API.user(req.params.userId)));
  } catch (err) {
    res.status(err?.response?.status || 503).json({ error: 'Roblox API error' });
  }
});

app.get('/api/stats', requireAuth, (req, res) => {
  const players = Array.from(store.players.values());
  const alerts = Array.from(store.alerts.values());
  const onlineNow = players.filter(p => p.currentPresence?.presenceType === 2).length;
  const statusCounts = { normal: 0, unusual: 0, attention: 0 };
  players.forEach(p => statusCounts[p.status || 'normal']++);
  res.json({
    totalPlayers: players.length,
    onlineNow,
    totalAlerts: alerts.length,
    unresolvedAlerts: alerts.filter(a => !a.resolved).length,
    statusCounts,
    recentAlerts: alerts.filter(a => !a.resolved).slice(0, 10)
  });
});

app.listen(PORT, () => {
  if (!passwordHash) process.stderr.write('WARN: no password hash — set PASSWORD_HASH env var or provide config.json\n');
});
