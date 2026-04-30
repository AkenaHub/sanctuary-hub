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
    
    // Admins bypass API key requirements
    if (ADMIN_IDS.includes(discordId)) {
        return next();
    }

    if (!apiKey) return res.status(401).json({ error: "API Key required to edit/upload." });

    const db = readDB();
    const keyData = db.apiKeys[apiKey];

    if (!keyData) return res.status(401).json({ error: "Invalid API Key." });
    if (Date.now() > keyData.expiresAt) return res.status(403).json({ error: "API Key has expired." });

    next();
};

// --- Discord OAuth2 Endpoints ---
app.get('/api/auth/discord', (req, res) => {
    const url = `https://discord.com/api/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=identify`;
    res.redirect(url);
});

app.get('/api/auth/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.send("No code provided.");

    try {
        // Exchange code for token
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
        
        // Fetch User Info
        const userResponse = await fetch('https://discord.com/api/users/@me', {
            headers: { authorization: `Bearer ${tokenData.access_token}` }
        });
        const userData = await userResponse.json();

        // Send a simple script to save the user data in localStorage and redirect to dashboard
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

// --- Admin Endpoints ---
app.post('/api/admin/generate-key', (req, res) => {
    const { discordId, days } = req.body;
    if (!ADMIN_IDS.includes(discordId)) return res.status(403).json({ error: "Unauthorized." });

    const db = readDB();
    const newKey = "SNC-" + crypto.randomBytes(8).toString('hex').toUpperCase();
    const expiresAt = Date.now() + (parseInt(days) * 24 * 60 * 60 * 1000);

    db.apiKeys[newKey] = { createdAt: Date.now(), expiresAt };
    writeDB(db);

    res.json({ key: newKey, expiresAt });
});

// --- Frontend Sync Endpoints ---
app.get('/api/sync', (req, res) => {
    const db = readDB();
    res.json({ projects: db.projects });
});

// Sync data (Requires API Key or Admin)
app.post('/api/sync', requireValidAccess, (req, res) => {
    const db = readDB();
    db.projects = req.body.projects;
    writeDB(db);
    res.json({ success: true });
});

// Check API Key Status Endpoint
app.post('/api/check-key', (req, res) => {
    const { apiKey } = req.body;
    const db = readDB();
    const keyData = db.apiKeys[apiKey];
    
    if (!keyData) return res.json({ valid: false });
    res.json({ valid: true, expiresAt: keyData.expiresAt });
});

// --- RAW SCRIPT URL ENDPOINT ---
app.get('/raw/:projectId/:scriptId', (req, res) => {
    const { projectId, scriptId } = req.params;
    
    // ANTI-SNOOP: Check if request is from a regular web browser
    const userAgent = req.headers['user-agent'] || "";
    const isBrowser = userAgent.includes("Mozilla") || userAgent.includes("Chrome") || userAgent.includes("Safari");

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
            
            // KILL SWITCH: If script is inactive, return the print statement
            if (script.status !== 'Active') {
                return res.send(`print("This script is no longer working. ID: ${scriptId}")`);
            }
            
            // Otherwise, send real code
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
