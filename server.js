const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' })); 
app.use(express.static(__dirname));

const dbPath = path.join(__dirname, 'database.json');

// --- Configuration & Admins ---
const ADMIN_IDS = ["1284247278957367337", "1282859051092414586"];

// These should be set in your Railway Environment Variables
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || "1499199968135876608";
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || "zAoxnpFlqfOgbN1fT8ZloyQgE9j6UzjG"; 
const REDIRECT_URI = process.env.REDIRECT_URI || "https://sanctuary-hub-production.up.railway.app/api/auth/callback";

// --- Database Helpers ---
const readDB = () => {
    try {
        if (fs.existsSync(dbPath)) {
            const data = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
            if (!data.apiKeys) data.apiKeys = {};
            if (!data.projects) data.projects = [];
            return data;
        }
    } catch (err) {
        console.error("Error reading database:", err);
    }
    return { projects: [], apiKeys: {}, sessions: {} }; 
};

const writeDB = (data) => {
    try {
        fs.writeFileSync(dbPath, JSON.stringify(data, null, 2));
    } catch (err) {
        console.error("Error saving database:", err);
    }
};

// --- Middleware: API Key Validation ---
const requireValidAccess = (req, res, next) => {
    const { apiKey, discordId } = req.body;
    if (ADMIN_IDS.includes(discordId)) return next();
    if (!apiKey) return res.status(401).json({ error: "API Key required to edit/upload." });

    const db = readDB();
    const keyData = db.apiKeys[apiKey];

    if (!keyData) return res.status(401).json({ error: "Invalid API Key." });
    if (Date.now() > keyData.expiresAt) return res.status(403).json({ error: "API Key has expired." });

    next();
};

// --- Discord OAuth2 Endpoints ---
app.get('/api/auth/discord', (req, res) => {
    const url = `https://discord.com/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=identify`;
    res.redirect(url);
});

app.get('/api/auth/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.send("No code provided.");

    try {
        const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            body: new URLSearchParams({
                client_id: DISCORD_CLIENT_ID,
                client_secret: DISCORD_CLIENT_SECRET,
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: REDIRECT_URI
            }),
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        const tokenData = await tokenResponse.json();
        const userResponse = await fetch('https://discord.com/api/users/@me', {
            headers: { authorization: `Bearer ${tokenData.access_token}` }
        });
        const userData = await userResponse.json();

        res.send(`
            <script>
                localStorage.setItem('sanctuary_user', JSON.stringify({
                    id: "${userData.id}",
                    username: "${userData.username}",
                    isAdmin: ${ADMIN_IDS.includes(userData.id)}
                }));
                window.location.href = "/";
            </script>
        `);
    } catch (err) {
        res.status(500).send("Authentication failed.");
    }
});

// --- API Key Linking Endpoint ---
app.post('/api/link-key', (req, res) => {
    const { apiKey, discordId, discordName } = req.body;
    const db = readDB();
    
    if (!db.apiKeys[apiKey]) return res.status(400).json({ error: "Invalid API Key" });
    
    // Link user details to the key for Admin visibility
    db.apiKeys[apiKey].userId = discordId;
    db.apiKeys[apiKey].username = discordName;
    writeDB(db);
    
    res.json({ success: true, expiresAt: db.apiKeys[apiKey].expiresAt });
});

app.post('/api/check-key', (req, res) => {
    const { apiKey } = req.body;
    const db = readDB();
    const keyData = db.apiKeys[apiKey];
    if (!keyData) return res.json({ valid: false });
    res.json({ valid: true, expiresAt: keyData.expiresAt });
});

// --- Admin Endpoints ---
const requireAdmin = (req, res, next) => {
    if (!ADMIN_IDS.includes(req.body.discordId)) return res.status(403).json({ error: "Unauthorized." });
    next();
};

app.post('/api/admin/keys', requireAdmin, (req, res) => {
    const db = readDB();
    res.json({ keys: db.apiKeys });
});

app.post('/api/admin/generate-key', requireAdmin, (req, res) => {
    const { days } = req.body;
    const db = readDB();
    // Lowercase hex string without SNC-
    const newKey = crypto.randomBytes(8).toString('hex').toLowerCase();
    const expiresAt = Date.now() + (parseInt(days) * 24 * 60 * 60 * 1000);

    db.apiKeys[newKey] = { createdAt: Date.now(), expiresAt, userId: null, username: null };
    writeDB(db);
    res.json({ key: newKey, expiresAt });
});

app.post('/api/admin/extend-key', requireAdmin, (req, res) => {
    const { targetKey, days } = req.body;
    const db = readDB();
    if (!db.apiKeys[targetKey]) return res.status(404).json({ error: "Key not found." });
    
    db.apiKeys[targetKey].expiresAt += (parseInt(days) * 24 * 60 * 60 * 1000);
    writeDB(db);
    res.json({ success: true });
});

app.post('/api/admin/revoke-key', requireAdmin, (req, res) => {
    const { targetKey } = req.body;
    const db = readDB();
    if (db.apiKeys[targetKey]) {
        delete db.apiKeys[targetKey];
        writeDB(db);
    }
    res.json({ success: true });
});

// --- Frontend Sync Endpoints ---
app.get('/api/sync', (req, res) => {
    res.json({ projects: readDB().projects });
});

app.post('/api/sync', requireValidAccess, (req, res) => {
    const db = readDB();
    db.projects = req.body.projects;
    writeDB(db);
    res.json({ success: true });
});

// --- RAW SCRIPT URL ENDPOINT (WITH EXECUTIONS & WEBHOOKS) ---
app.get('/raw/:projectId/:scriptId', (req, res) => {
    const { projectId, scriptId } = req.params;
    
    // ANTI-SNOOP FIX: Check 'Accept' headers instead of User-Agent. 
    // Browsers specifically ask for 'text/html' when visiting a link, but executors/scripts usually ask for '*/*' or 'text/plain'.
    const acceptHeader = req.headers['accept'] || "";
    const isBrowser = acceptHeader.includes("text/html");

    if (isBrowser) {
        res.type('text/plain');
        return res.send(`-- Script ID: ${scriptId}`);
    }

    const db = readDB();
    const project = db.projects.find(p => p.id === projectId);
    
    if (project) {
        const script = project.scripts.find(s => s.id === scriptId);
        if (script) {
            res.type('text/plain');
            
            if (script.status !== 'Active') {
                return res.send(`print("This script is no longer working. ID: ${scriptId}")`);
            }
            
            // Increment Executions
            script.executions = (script.executions || 0) + 1;
            writeDB(db);

            // Trigger Discord Webhook Alert
            if (project.webhookUrl) {
                const executor = userAgent.substring(0, 60) || "Unknown Executor";
                try {
                    fetch(project.webhookUrl, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            embeds: [{
                                title: "🚀 Script Executed",
                                color: 0x4f46e5,
                                fields: [
                                    { name: "Project", value: project.name, inline: true },
                                    { name: "Script", value: script.name, inline: true },
                                    { name: "Executor", value: executor, inline: true },
                                    { name: "Total Executions", value: script.executions.toString(), inline: true }
                                ],
                                timestamp: new Date().toISOString()
                            }]
                        })
                    }).catch(()=>{}); // Ignore failures to not block script
                } catch(e) {}
            }

            return res.send(script.code || '-- Error: Uploaded script file was completely empty.');
        }
    }
    
    res.status(404).send('-- Error: Script or Project not found.');
});

// --- CUSTOM LOADER URL ENDPOINT ---
app.get('/loader/:projectId', (req, res) => {
    const { projectId } = req.params;
    const db = readDB();
    const project = db.projects.find(p => p.id === projectId);
    
    if (project) {
        res.type('text/plain');
        return res.send(project.loaderCode || '-- Error: Custom Loader code is completely empty.');
    }
    res.status(404).send('-- Error: Project not found.');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Sanctuary Hub API is successfully running on port ${PORT}`);
});
