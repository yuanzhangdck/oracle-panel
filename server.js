const express = require('express');
const multer = require('multer');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const OracleClient = require('./oci-client');
const { db, init } = require('./database');
const { execSync } = require('child_process');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = Number(process.env.PORT || 3001);
const PANEL_PASSWORD = process.env.PANEL_PASSWORD || 'oracle123456';
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const SESSION_COOKIE = 'panel_session';
const INSTANCE_CACHE_TTL_MS = 30 * 60 * 1000;
const MONTHLY_SCHEDULE_CHECK_MS = 60 * 1000;

const publicDir = path.join(__dirname, 'public');
const uploadsDir = path.join(__dirname, 'uploads');
const settingsPath = path.join(__dirname, 'data', 'settings.json');
const schedulePath = path.join(__dirname, 'data', 'monthly-ip-schedule.json');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const upload = multer({ dest: uploadsDir });
const sessions = new Map(); // token -> expiresAt
const instanceCache = new Map(); // keyId -> { expiresAt, instances }
const runningScheduleIds = new Set();
const runningGrabTasks = new Map(); // grabTaskId -> intervalHandle

init();

function dbRun(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function(err) { err ? reject(err) : resolve(this); });
    });
}
function dbAll(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => { err ? reject(err) : resolve(rows); });
    });
}
function dbGet(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => { err ? reject(err) : resolve(row); });
    });
}

function persistLog(message, level = 'info') {
    db.run(`INSERT INTO logs (level, message) VALUES (?, ?)`, [level, message]);
    io.emit('log', message);
}

function logAccess(action, detail, ip) {
    db.run(`INSERT INTO access_logs (action, detail, ip) VALUES (?, ?, ?)`, [action, detail, ip]);
}

function getClientIp(req) {
    return req.headers['x-real-ip'] || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
}

app.use(express.json());

function defaultSettings() {
    return {
        auth: {
            passwordSalt: '',
            passwordHash: ''
        },
        telegram: {
            botToken: '',
            chatIds: []
        }
    };
}

function loadSettings() {
    try {
        if (!fs.existsSync(settingsPath)) return defaultSettings();
        const raw = fs.readFileSync(settingsPath, 'utf8');
        const parsed = JSON.parse(raw);
        return {
            auth: {
                passwordSalt: String(parsed?.auth?.passwordSalt || ''),
                passwordHash: String(parsed?.auth?.passwordHash || '')
            },
            telegram: {
                botToken: String(parsed?.telegram?.botToken || ''),
                chatIds: Array.isArray(parsed?.telegram?.chatIds) ? parsed.telegram.chatIds.map(v => String(v).trim()).filter(Boolean) : []
            }
        };
    } catch (_) {
        return defaultSettings();
    }
}

function saveSettings(nextSettings) {
    fs.writeFileSync(settingsPath, JSON.stringify(nextSettings, null, 2), 'utf8');
}

function hashPassword(password, salt) {
    return crypto.scryptSync(password, salt, 64).toString('hex');
}

function verifyPanelPassword(password) {
    const envPassword = process.env.PANEL_PASSWORD;
    if (envPassword) return password === envPassword;
    const settings = loadSettings();
    if (settings.auth.passwordSalt && settings.auth.passwordHash) {
        return hashPassword(password, settings.auth.passwordSalt) === settings.auth.passwordHash;
    }
    return password === PANEL_PASSWORD;
}

function setPanelPassword(newPassword) {
    const settings = loadSettings();
    const salt = crypto.randomBytes(16).toString('hex');
    settings.auth.passwordSalt = salt;
    settings.auth.passwordHash = hashPassword(newPassword, salt);
    saveSettings(settings);
}

function defaultSchedules() {
    return { items: [] };
}

function sanitizeTime(time) {
    const t = String(time || '03:00').trim();
    return /^\d{2}:\d{2}$/.test(t) ? t : '03:00';
}

function monthKey(date) {
    return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
}

function parseTime(time) {
    const [h, m] = sanitizeTime(time).split(':').map(Number);
    return { h, m };
}

function pickRandomDay(year, monthIndex) {
    const lastDay = new Date(year, monthIndex + 1, 0).getDate();
    const maxDay = Math.min(28, lastDay);
    return crypto.randomInt(1, maxDay + 1);
}

function buildNextRunAt(time, baseDate = new Date()) {
    let y = baseDate.getFullYear();
    let m = baseDate.getMonth();
    const { h, m: min } = parseTime(time);
    let day = pickRandomDay(y, m);
    let next = new Date(y, m, day, h, min, 0, 0);
    if (next <= baseDate) {
        m += 1;
        if (m > 11) {
            m = 0;
            y += 1;
        }
        day = pickRandomDay(y, m);
        next = new Date(y, m, day, h, min, 0, 0);
    }
    return next.toISOString();
}

function normalizeScheduleItem(item) {
    return {
        keyId: String(item.keyId),
        instanceId: String(item.instanceId),
        enabled: Boolean(item.enabled),
        time: sanitizeTime(item.time),
        nextRunAt: item.nextRunAt ? String(item.nextRunAt) : null,
        lastRunMonth: item.lastRunMonth ? String(item.lastRunMonth) : null
    };
}

function loadSchedules() {
    try {
        if (!fs.existsSync(schedulePath)) return defaultSchedules();
        const raw = fs.readFileSync(schedulePath, 'utf8');
        const parsed = JSON.parse(raw);
        const items = Array.isArray(parsed?.items) ? parsed.items.map(normalizeScheduleItem) : [];
        return { items };
    } catch (_) {
        return defaultSchedules();
    }
}

function saveSchedules(schedules) {
    fs.writeFileSync(schedulePath, JSON.stringify(schedules, null, 2), 'utf8');
}

function upsertScheduleItem(keyId, instanceId, enabled, time) {
    const schedules = loadSchedules();
    const idx = schedules.items.findIndex(i => i.keyId === String(keyId) && i.instanceId === String(instanceId));
    const normalizedTime = sanitizeTime(time);
    const now = new Date();
    const nextRunAt = enabled ? buildNextRunAt(normalizedTime, now) : null;
    const item = {
        keyId: String(keyId),
        instanceId: String(instanceId),
        enabled: Boolean(enabled),
        time: normalizedTime,
        nextRunAt,
        lastRunMonth: null
    };
    if (idx >= 0) schedules.items[idx] = item;
    else schedules.items.push(item);
    saveSchedules(schedules);
    return item;
}

function listSchedulesByKeyId(keyId) {
    const schedules = loadSchedules();
    return schedules.items.filter(i => i.keyId === String(keyId));
}

function removeSchedulesByKeyId(keyId) {
    const schedules = loadSchedules();
    schedules.items = schedules.items.filter(i => i.keyId !== String(keyId));
    saveSchedules(schedules);
}

function updateAfterMonthlyRun(keyId, instanceId, success, now = new Date()) {
    const schedules = loadSchedules();
    const idx = schedules.items.findIndex(i => i.keyId === String(keyId) && i.instanceId === String(instanceId));
    if (idx < 0) return;
    const item = schedules.items[idx];
    if (!item.enabled) return;
    if (success) {
        item.lastRunMonth = monthKey(now);
        // Force next run into next month
        const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 1);
        item.nextRunAt = buildNextRunAt(item.time, nextMonth);
    } else {
        // Retry in 30 minutes on failure
        const retry = new Date(now.getTime() + 30 * 60 * 1000);
        item.nextRunAt = retry.toISOString();
    }
    schedules.items[idx] = normalizeScheduleItem(item);
    saveSchedules(schedules);
}

function parseCookies(cookieHeader = '') {
    const out = {};
    cookieHeader.split(';').forEach(part => {
        const i = part.indexOf('=');
        if (i > 0) {
            const key = part.slice(0, i).trim();
            const value = part.slice(i + 1).trim();
            out[key] = decodeURIComponent(value);
        }
    });
    return out;
}

function createSessionToken() {
    return crypto.randomBytes(32).toString('hex');
}

function hasValidSessionFromCookieHeader(cookieHeader = '') {
    const cookies = parseCookies(cookieHeader);
    const token = cookies[SESSION_COOKIE];
    if (!token) return false;
    const expiresAt = sessions.get(token);
    if (!expiresAt || expiresAt < Date.now()) {
        sessions.delete(token);
        return false;
    }
    return true;
}

function requireAuth(req, res, next) {
    const openPaths = new Set([
        '/login.html',
        '/api/login',
        '/favicon.ico',
        '/favicon.svg',
        '/favicon.png',
        '/logo.svg'
    ]);
    if (openPaths.has(req.path)) return next();

    const ok = hasValidSessionFromCookieHeader(req.headers.cookie || '');
    if (ok) return next();

    if (req.path.startsWith('/api/')) {
        return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' });
    }
    return res.redirect('/login.html');
}

async function sendTelegram(text) {
    const settings = loadSettings();
    const botToken = settings.telegram.botToken;
    const chatIds = settings.telegram.chatIds;
    if (!botToken || chatIds.length === 0) return;
    const url = `https://api.telegram.org/bot${botToken}/sendMessage`;
    const tasks = chatIds.map(chatId =>
        fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: chatId, text })
        })
    );
    const results = await Promise.allSettled(tasks);
    results.forEach((r, idx) => {
        if (r.status === 'rejected') {
            console.error(`Telegram notify failed for chat ${chatIds[idx]}:`, r.reason && r.reason.message ? r.reason.message : r.reason);
        }
    });
}

function createClientFromKeyRow(row) {
    return new OracleClient({
        user: row.user_ocid,
        fingerprint: row.fingerprint,
        tenancy: row.tenancy_ocid,
        region: row.region,
        keyFile: row.key_file_path
    });
}

async function performChangeIp(keyId, instanceId, row, source = 'manual') {
    const client = createClientFromKeyRow(row);
    persistLog(`Changing IP for ${instanceId}...`);

    // Get old IP from cache
    const cache = instanceCache.get(String(keyId));
    const oldIp = cache?.instances?.find(i => i.id === instanceId)?.public_ip || '';
    const instName = cache?.instances?.find(i => i.id === instanceId)?.name || '';

    const newIp = await client.changePublicIp(instanceId);
    persistLog(`Success! New IP: ${newIp}`);

    // Record history
    db.run(`INSERT INTO ip_history (key_id, instance_id, instance_name, ip_type, old_ip, new_ip, source) VALUES (?,?,?,?,?,?,?)`,
        [keyId, instanceId, instName, 'ipv4', oldIp, newIp, source]);

    if (cache && cache.instances) {
        cache.instances = cache.instances.map(i => (i.id === instanceId ? { ...i, public_ip: newIp } : i));
        cache.expiresAt = Date.now() + INSTANCE_CACHE_TTL_MS;
        instanceCache.set(String(keyId), cache);
    }

    const prefix = source === 'schedule' ? '[月度定时]' : '[手动]';
    await sendTelegram(`[Oracle Panel] ${prefix} 换IP成功\n实例: ${instanceId}\n新IP: ${newIp}`);
    return newIp;
}

async function performChangeIpv6(keyId, instanceId, row) {
    const client = createClientFromKeyRow(row);
    persistLog(`Changing IPv6 for ${instanceId}...`);

    const cache = instanceCache.get(String(keyId));
    const oldIpv6 = cache?.instances?.find(i => i.id === instanceId)?.ipv6 || '';
    const instName = cache?.instances?.find(i => i.id === instanceId)?.name || '';

    const newIpv6 = await client.changeIpv6(instanceId);
    persistLog(`Success! New IPv6: ${newIpv6}`);

    db.run(`INSERT INTO ip_history (key_id, instance_id, instance_name, ip_type, old_ip, new_ip, source) VALUES (?,?,?,?,?,?,?)`,
        [keyId, instanceId, instName, 'ipv6', oldIpv6, newIpv6, 'manual']);

    if (cache && cache.instances) {
        cache.instances = cache.instances.map(i => (i.id === instanceId ? { ...i, ipv6: newIpv6 } : i));
        cache.expiresAt = Date.now() + INSTANCE_CACHE_TTL_MS;
        instanceCache.set(String(keyId), cache);
    }

    await sendTelegram(`[Oracle Panel] [手动] 换IPv6成功\n实例: ${instanceId}\n新IPv6: ${newIpv6}`);
    return newIpv6;
}

setInterval(() => {
    const now = Date.now();
    for (const [token, expiresAt] of sessions.entries()) {
        if (expiresAt < now) sessions.delete(token);
    }
}, 5 * 60 * 1000).unref();

app.post('/api/login', (req, res) => {
    const { password } = req.body || {};
    const ip = getClientIp(req);
    if (!password || !verifyPanelPassword(password)) {
        logAccess('login_failed', '密码错误', ip);
        return res.status(401).json({ ok: false, error: '密码错误' });
    }
    const token = createSessionToken();
    sessions.set(token, Date.now() + SESSION_TTL_MS);
    res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`);
    logAccess('login', '登录成功', ip);
    res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
    const cookies = parseCookies(req.headers.cookie || '');
    const token = cookies[SESSION_COOKIE];
    if (token) sessions.delete(token);
    res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
    logAccess('logout', '退出登录', getClientIp(req));
    res.json({ ok: true });
});

app.use(requireAuth);
app.use(express.static(publicDir));

app.get('/api/auth/status', (req, res) => {
    const settings = loadSettings();
    res.json({
        ok: true,
        telegramConfigured: Boolean(settings.telegram.botToken && settings.telegram.chatIds.length > 0),
        hasCustomPassword: Boolean(settings.auth.passwordSalt && settings.auth.passwordHash)
    });
});

app.post('/api/password/change', (req, res) => {
    const currentPassword = String(req.body?.currentPassword || '');
    const newPassword = String(req.body?.newPassword || '');
    if (!currentPassword || !newPassword) {
        return res.json({ ok: false, error: '当前密码和新密码不能为空' });
    }
    if (!verifyPanelPassword(currentPassword)) {
        return res.json({ ok: false, error: '当前密码错误' });
    }
    if (newPassword.length < 8) {
        return res.json({ ok: false, error: '新密码至少 8 位' });
    }
    setPanelPassword(newPassword);
    res.json({ ok: true });
});

app.get('/api/notify/config', (req, res) => {
    const settings = loadSettings();
    res.json({
        ok: true,
        botToken: settings.telegram.botToken,
        chatIds: settings.telegram.chatIds.join(',')
    });
});

app.post('/api/notify/config', (req, res) => {
    const botToken = String(req.body?.botToken || '').trim();
    const chatIds = String(req.body?.chatIds || '')
        .split(',')
        .map(s => s.trim())
        .filter(Boolean);
    const settings = loadSettings();
    settings.telegram.botToken = botToken;
    settings.telegram.chatIds = chatIds;
    saveSettings(settings);
    res.json({ ok: true, telegramConfigured: Boolean(botToken && chatIds.length > 0) });
});

app.post('/api/notify/test', async (req, res) => {
    try {
        await sendTelegram(`[Oracle Panel] Test notification at ${new Date().toISOString()}`);
        res.json({ ok: true });
    } catch (e) {
        res.json({ ok: false, error: e.message });
    }
});

app.post('/api/keys', upload.single('keyFile'), async (req, res) => {
    try {
        const { name, user, fingerprint, tenancy, region } = req.body;
        if (!req.file) return res.json({ ok: false, error: '请上传 Key 文件' });

        const keyFile = path.resolve(req.file.path);

        try {
            execSync(`openssl rsa -in "${keyFile}" -out "${keyFile}.conv"`, { stdio: 'pipe' });
            if (fs.existsSync(`${keyFile}.conv`)) {
                fs.renameSync(`${keyFile}.conv`, keyFile);
            }
        } catch (_) {
            // Keep original content if conversion fails.
        }

        const client = new OracleClient({ user, fingerprint, tenancy, region, keyFile });
        const test = await client.testConnection();

        if (!test.ok) {
            fs.unlinkSync(keyFile);
            return res.json({ ok: false, error: test.error });
        }

        db.run(
            `INSERT INTO api_keys (name, user_ocid, fingerprint, tenancy_ocid, region, key_file_path) VALUES (?, ?, ?, ?, ?, ?)`,
            [name, user, fingerprint, tenancy, region, keyFile],
            async function(err) {
                if (err) return res.json({ ok: false, error: err.message });
                await sendTelegram(`[Oracle Panel] 账号已添加: ${name || '(未命名)'} (${region})`);
                res.json({ ok: true, id: this.lastID });
            }
        );
    } catch (e) {
        if (req.file && req.file.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        res.json({ ok: false, error: e.message });
    }
});

app.get('/api/keys', (req, res) => {
    db.all(`SELECT id, name, region FROM api_keys`, (err, rows) => {
        if (err) return res.json([]);
        res.json(rows);
    });
});

app.delete('/api/keys/:id', (req, res) => {
    const id = req.params.id;
    db.get(`SELECT name, key_file_path FROM api_keys WHERE id = ?`, [id], (err, row) => {
        if (err || !row) return res.json({ ok: false, error: 'Not found' });

        const keyPath = path.isAbsolute(row.key_file_path) ? row.key_file_path : path.join(__dirname, row.key_file_path);
        try {
            if (fs.existsSync(keyPath)) fs.unlinkSync(keyPath);
        } catch (e) {
            console.error('Failed to delete key file:', e.message);
        }

        db.run(`DELETE FROM api_keys WHERE id = ?`, [id], async delErr => {
            if (delErr) return res.json({ ok: false, error: delErr.message });
            instanceCache.delete(String(id));
            removeSchedulesByKeyId(String(id));
            await sendTelegram(`[Oracle Panel] 账号已删除: ${row.name || id}`);
            res.json({ ok: true });
        });
    });
});

app.get('/api/instances/:keyId', async (req, res) => {
    const keyId = req.params.keyId;
    const forceRefresh = req.query.refresh === '1';

    db.get(`SELECT * FROM api_keys WHERE id = ?`, [keyId], async (err, row) => {
        if (err || !row) return res.json({ ok: false, error: 'Key not found' });

        try {
            if (!forceRefresh) {
                const cached = instanceCache.get(String(keyId));
                if (cached && cached.expiresAt > Date.now()) {
                    return res.json({ ok: true, instances: cached.instances, cached: true });
                }
            }

            const client = new OracleClient({
                user: row.user_ocid,
                fingerprint: row.fingerprint,
                tenancy: row.tenancy_ocid,
                region: row.region,
                keyFile: row.key_file_path
            });

            const instances = await client.listInstances();
            instanceCache.set(String(keyId), {
                expiresAt: Date.now() + INSTANCE_CACHE_TTL_MS,
                instances
            });
            res.json({ ok: true, instances, cached: false });
        } catch (e) {
            res.json({ ok: false, error: e.message });
        }
    });
});

app.get('/api/instance/:keyId/:instanceId', async (req, res) => {
    const { keyId, instanceId } = req.params;
    db.get(`SELECT * FROM api_keys WHERE id = ?`, [keyId], async (err, row) => {
        if (err || !row) return res.json({ ok: false, error: 'Key not found' });
        try {
            const client = new OracleClient({
                user: row.user_ocid,
                fingerprint: row.fingerprint,
                tenancy: row.tenancy_ocid,
                region: row.region,
                keyFile: row.key_file_path
            });
            const instance = await client.getInstanceById(instanceId);

            const cache = instanceCache.get(String(keyId));
            if (cache && cache.instances) {
                cache.instances = cache.instances.map(i => (i.id === instanceId ? instance : i));
                cache.expiresAt = Date.now() + INSTANCE_CACHE_TTL_MS;
                instanceCache.set(String(keyId), cache);
            }

            res.json({ ok: true, instance });
        } catch (e) {
            res.json({ ok: false, error: e.message });
        }
    });
});

app.get('/api/schedules/:keyId', (req, res) => {
    const keyId = req.params.keyId;
    const items = listSchedulesByKeyId(keyId);
    res.json({ ok: true, items });
});

app.post('/api/schedule/update', (req, res) => {
    const keyId = String(req.body?.keyId || '').trim();
    const instanceId = String(req.body?.instanceId || '').trim();
    const enabled = Boolean(req.body?.enabled);
    const time = sanitizeTime(req.body?.time || '03:00');
    if (!keyId || !instanceId) {
        return res.json({ ok: false, error: 'keyId / instanceId 不能为空' });
    }
    const item = upsertScheduleItem(keyId, instanceId, enabled, time);
    res.json({ ok: true, item });
});

app.post('/api/change-ip', async (req, res) => {
    const { keyId, instanceId } = req.body;
    db.get(`SELECT * FROM api_keys WHERE id = ?`, [keyId], async (err, row) => {
        if (err || !row) return res.json({ ok: false, error: 'Key not found' });

        try {
            const newIp = await performChangeIp(keyId, instanceId, row, 'manual');
            res.json({ ok: true, newIp });
        } catch (e) {
            persistLog(`Error: ${e.message}`, 'error');
            console.error('Change IP failed:', {
                message: e.message,
                statusCode: e.statusCode,
                serviceCode: e.serviceCode,
                opcRequestId: e.opcRequestId
            });
            await sendTelegram(`[Oracle Panel] [手动] 换IP失败\n实例: ${instanceId}\n错误: ${e.message}`);
            res.json({ ok: false, error: e.message });
        }
    });
});

app.post('/api/change-ipv6', async (req, res) => {
    const { keyId, instanceId } = req.body;
    db.get(`SELECT * FROM api_keys WHERE id = ?`, [keyId], async (err, row) => {
        if (err || !row) return res.json({ ok: false, error: 'Key not found' });

        try {
            const newIpv6 = await performChangeIpv6(keyId, instanceId, row);
            res.json({ ok: true, newIpv6 });
        } catch (e) {
            persistLog(`Error: ${e.message}`, 'error');
            console.error('Change IPv6 failed:', {
                message: e.message,
                statusCode: e.statusCode,
                serviceCode: e.serviceCode,
                opcRequestId: e.opcRequestId
            });
            await sendTelegram(`[Oracle Panel] [手动] 换IPv6失败\n实例: ${instanceId}\n错误: ${e.message}`);
            res.json({ ok: false, error: e.message });
        }
    });
});

app.post('/api/enable-ipv6', async (req, res) => {
    const { keyId, instanceId } = req.body;
    db.get(`SELECT * FROM api_keys WHERE id = ?`, [keyId], async (err, row) => {
        if (err || !row) return res.json({ ok: false, error: 'Key not found' });
        try {
            const client = createClientFromKeyRow(row);
            persistLog(`Enabling IPv6 for ${instanceId}...`);
            const newIpv6 = await client.enableIpv6(instanceId);
            persistLog(`IPv6 enabled! Address: ${newIpv6}`);

            const cache = instanceCache.get(String(keyId));
            if (cache && cache.instances) {
                cache.instances = cache.instances.map(i => (i.id === instanceId ? { ...i, ipv6: newIpv6 } : i));
                instanceCache.set(String(keyId), cache);
            }

            logAccess('enable_ipv6', `实例 ${instanceId} 附加IPv6: ${newIpv6}`, getClientIp(req));
            await sendTelegram(`[Oracle Panel] 附加IPv6成功\n实例: ${instanceId}\nIPv6: ${newIpv6}`);
            res.json({ ok: true, ipv6: newIpv6 });
        } catch (e) {
            persistLog(`Enable IPv6 failed: ${e.message}`, 'error');
            res.json({ ok: false, error: e.message });
        }
    });
});

app.get('/api/traffic/:keyId/:instanceId', async (req, res) => {
    const { keyId, instanceId } = req.params;
    db.get(`SELECT * FROM api_keys WHERE id = ?`, [keyId], async (err, row) => {
        if (err || !row) return res.json({ ok: false, error: 'Key not found' });
        try {
            const client = createClientFromKeyRow(row);
            const traffic = await client.getMonthlyTraffic(instanceId);
            const now = new Date();
            res.json({
                ok: true,
                year: now.getFullYear(),
                month: now.getMonth() + 1,
                bytesIn: traffic.bytesIn,
                bytesOut: traffic.bytesOut
            });
        } catch (e) {
            console.error('Traffic query failed:', e.message);
            res.json({ ok: false, error: e.message });
        }
    });
});

// === Persistent Logs API ===
app.get('/api/logs', async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 200, 1000);
    const rows = await dbAll(`SELECT id, level, message, created_at FROM logs ORDER BY id DESC LIMIT ?`, [limit]);
    res.json({ ok: true, items: rows });
});

// === IP History API ===
app.get('/api/ip-history', async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const rows = await dbAll(`SELECT * FROM ip_history ORDER BY id DESC LIMIT ?`, [limit]);
    res.json({ ok: true, items: rows });
});

// === Access Logs API ===
app.get('/api/access-logs', async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const rows = await dbAll(`SELECT * FROM access_logs ORDER BY id DESC LIMIT ?`, [limit]);
    res.json({ ok: true, items: rows });
});

// === Grab (Auto-create Instance) APIs ===
app.get('/api/grab/options/:keyId', async (req, res) => {
    const row = await dbGet(`SELECT * FROM api_keys WHERE id = ?`, [req.params.keyId]);
    if (!row) return res.json({ ok: false, error: 'Key not found' });
    try {
        const client = createClientFromKeyRow(row);
        const [ads, subnets, images] = await Promise.all([
            client.listAvailabilityDomains(),
            client.listSubnets(),
            client.listImages()
        ]);
        res.json({ ok: true, availabilityDomains: ads, subnets, images });
    } catch (e) {
        res.json({ ok: false, error: e.message });
    }
});

app.get('/api/grab/tasks', async (req, res) => {
    const rows = await dbAll(`SELECT g.*, k.name as key_name, k.region FROM grab_tasks g LEFT JOIN api_keys k ON g.key_id = k.id ORDER BY g.id DESC`);
    res.json({ ok: true, items: rows });
});

app.post('/api/grab/tasks', async (req, res) => {
    const { keyId, name, shape, ocpus, memoryGb, imageId, subnetId, availabilityDomain, sshPublicKey, rootPassword, intervalSeconds } = req.body;
    if (!keyId || !shape || !imageId || !subnetId || !availabilityDomain) {
        return res.json({ ok: false, error: '缺少必填参数' });
    }
    try {
        const result = await dbRun(
            `INSERT INTO grab_tasks (key_id, name, shape, ocpus, memory_gb, image_id, subnet_id, availability_domain, ssh_public_key, root_password, interval_seconds, status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
            [keyId, name || 'grabbed-instance', shape, ocpus || 1, memoryGb || 6, imageId, subnetId, availabilityDomain, sshPublicKey || '', rootPassword || '', intervalSeconds || 60, 'running']
        );
        const taskId = result.lastID;
        logAccess('grab_create', `创建抢机任务 #${taskId}: ${shape}`, getClientIp(req));
        startGrabTask(taskId);
        res.json({ ok: true, id: taskId });
    } catch (e) {
        res.json({ ok: false, error: e.message });
    }
});

app.post('/api/grab/tasks/:id/pause', async (req, res) => {
    const id = req.params.id;
    stopGrabTask(Number(id));
    await dbRun(`UPDATE grab_tasks SET status = 'paused' WHERE id = ? AND status = 'running'`, [id]);
    logAccess('grab_pause', `暂停抢机任务 #${id}`, getClientIp(req));
    res.json({ ok: true });
});

app.post('/api/grab/tasks/:id/resume', async (req, res) => {
    const id = req.params.id;
    await dbRun(`UPDATE grab_tasks SET status = 'running' WHERE id = ? AND status = 'paused'`, [id]);
    logAccess('grab_resume', `恢复抢机任务 #${id}`, getClientIp(req));
    startGrabTask(Number(id));
    res.json({ ok: true });
});

app.delete('/api/grab/tasks/:id', async (req, res) => {
    const id = req.params.id;
    stopGrabTask(Number(id));
    await dbRun(`DELETE FROM grab_tasks WHERE id = ?`, [id]);
    logAccess('grab_delete', `删除抢机任务 #${id}`, getClientIp(req));
    res.json({ ok: true });
});

// === Grab Task Runner ===
async function runGrabAttempt(taskId) {
    const task = await dbGet(`SELECT g.*, k.* FROM grab_tasks g JOIN api_keys k ON g.key_id = k.id WHERE g.id = ?`, [taskId]);
    if (!task || task.status !== 'running') { stopGrabTask(taskId); return; }

    try {
        const client = createClientFromKeyRow({ user_ocid: task.user_ocid, fingerprint: task.fingerprint, tenancy_ocid: task.tenancy_ocid, region: task.region, key_file_path: task.key_file_path });
        persistLog(`[抢机 #${taskId}] 第 ${task.attempt_count + 1} 次尝试创建 ${task.shape}...`);

        const inst = await client.launchInstance({
            name: task.name,
            shape: task.shape,
            ocpus: task.ocpus,
            memoryGb: task.memory_gb,
            imageId: task.image_id,
            subnetId: task.subnet_id,
            availabilityDomain: task.availability_domain,
            sshPublicKey: task.ssh_public_key,
            rootPassword: task.root_password
        });

        // Success!
        stopGrabTask(taskId);
        await dbRun(`UPDATE grab_tasks SET status = 'success', attempt_count = attempt_count + 1, last_attempt_at = datetime('now') WHERE id = ?`, [taskId]);
        persistLog(`[抢机 #${taskId}] 成功！实例: ${inst.name} (${inst.id})`);
        await sendTelegram(`[Oracle Panel] [抢机] 成功创建实例！\n名称: ${inst.name}\n规格: ${task.shape}\nID: ${inst.id}`);
        // Clear instance cache to force refresh
        instanceCache.delete(String(task.key_id));
    } catch (e) {
        await dbRun(`UPDATE grab_tasks SET attempt_count = attempt_count + 1, last_attempt_at = datetime('now'), last_error = ? WHERE id = ?`, [e.message, taskId]);
        const count = (task.attempt_count || 0) + 1;
        if (count % 10 === 0) {
            persistLog(`[抢机 #${taskId}] 已尝试 ${count} 次，最近错误: ${e.message}`, 'warn');
        }
    }
}

function startGrabTask(taskId) {
    if (runningGrabTasks.has(taskId)) return;
    dbGet(`SELECT * FROM grab_tasks WHERE id = ? AND status = 'running'`, [taskId]).then(task => {
        if (!task) return;
        const interval = Math.max((task.interval_seconds || 60) * 1000, 10000);
        // Run immediately then on interval
        runGrabAttempt(taskId);
        const handle = setInterval(() => runGrabAttempt(taskId), interval);
        runningGrabTasks.set(taskId, handle);
    });
}

function stopGrabTask(taskId) {
    const handle = runningGrabTasks.get(taskId);
    if (handle) { clearInterval(handle); runningGrabTasks.delete(taskId); }
}

// Resume running grab tasks on startup
db.all(`SELECT id FROM grab_tasks WHERE status = 'running'`, (err, rows) => {
    if (!err && rows) rows.forEach(r => startGrabTask(r.id));
});

async function runMonthlyScheduleTick() {
    const now = new Date();
    const schedules = loadSchedules();
    let changed = false;
    for (const item of schedules.items) {
        if (item.enabled && !item.nextRunAt) {
            item.nextRunAt = buildNextRunAt(item.time, now);
            changed = true;
        }
    }
    if (changed) saveSchedules(schedules);

    const dueItems = schedules.items.filter(item =>
        item.enabled &&
        item.nextRunAt &&
        new Date(item.nextRunAt).getTime() <= now.getTime() &&
        item.lastRunMonth !== monthKey(now)
    );

    for (const item of dueItems) {
        const runId = `${item.keyId}:${item.instanceId}`;
        if (runningScheduleIds.has(runId)) continue;
        runningScheduleIds.add(runId);

        db.get(`SELECT * FROM api_keys WHERE id = ?`, [item.keyId], async (err, row) => {
            try {
                if (err || !row) {
                    console.error('[Schedule] key not found:', item.keyId, err ? err.message : '');
                    updateAfterMonthlyRun(item.keyId, item.instanceId, false, new Date());
                    return;
                }
                await performChangeIp(item.keyId, item.instanceId, row, 'schedule');
                updateAfterMonthlyRun(item.keyId, item.instanceId, true, new Date());
            } catch (e) {
                console.error('[Schedule] monthly change-ip failed:', e.message);
                await sendTelegram(`[Oracle Panel] [月度定时] 换IP失败\n实例: ${item.instanceId}\n错误: ${e.message}`);
                updateAfterMonthlyRun(item.keyId, item.instanceId, false, new Date());
            } finally {
                runningScheduleIds.delete(runId);
            }
        });
    }
}

setInterval(() => {
    runMonthlyScheduleTick().catch(e => {
        console.error('[Schedule] tick failed:', e.message);
    });
}, MONTHLY_SCHEDULE_CHECK_MS).unref();

io.use((socket, next) => {
    const ok = hasValidSessionFromCookieHeader(socket.handshake.headers.cookie || '');
    if (!ok) return next(new Error('UNAUTHORIZED'));
    next();
});

io.on('connection', () => {
    console.log('Client connected');
});

server.listen(PORT, () => {
    console.log(`Oracle Panel running on port ${PORT}`);
    const settings = loadSettings();
    if (!process.env.PANEL_PASSWORD && !(settings.auth.passwordSalt && settings.auth.passwordHash)) {
        console.warn('Panel password not customized yet. Using default password "oracle123456".');
    }
    if (!settings.telegram.botToken || settings.telegram.chatIds.length === 0) {
        console.warn('Telegram notification is disabled. Configure it in Panel -> API Keys -> Telegram 通知.');
    }
});
