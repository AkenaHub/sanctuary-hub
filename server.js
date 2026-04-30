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
const REDIRECT_URI = process.env.REDIRECT_URI || "https://luau-auth-production.up.railway.app/api/auth/callback";

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
                    avatar: "${userData.avatar || ''}",
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
// SCOPED VISIBILITY: Users only get their own projects (Admins get all)
app.get('/api/sync', (req, res) => {
    const { discordId } = req.query;
    const db = readDB();
    if (!discordId) return res.json({ projects: [] });

    const isAdmin = ADMIN_IDS.includes(discordId);

    // Retroactive Fix: If a project lacks an owner (from before this update), assign it to the requester
    let needsSave = false;
    db.projects.forEach(p => {
        if (!p.ownerId) { p.ownerId = discordId; needsSave = true; }
    });
    if (needsSave) writeDB(db);

    const userProjects = isAdmin ? db.projects : db.projects.filter(p => p.ownerId === discordId);
    res.json({ projects: userProjects });
});

// MULTI-USER MERGE: Safely update only the projects the user actually owns
app.post('/api/sync', requireValidAccess, (req, res) => {
    const db = readDB();
    const incomingProjects = req.body.projects;
    const discordId = req.body.discordId;
    const isAdmin = ADMIN_IDS.includes(discordId);

    const existingProjectsMap = new Map(db.projects.map(p => [p.id, p]));

    incomingProjects.forEach(incomingProj => {
        if (!incomingProj.ownerId) incomingProj.ownerId = discordId;
        const existing = existingProjectsMap.get(incomingProj.id);

        if (existing) {
            // Update if user is admin or owner
            if (isAdmin || existing.ownerId === discordId) {
                existingProjectsMap.set(incomingProj.id, incomingProj);
            }
        } else {
            existingProjectsMap.set(incomingProj.id, incomingProj);
        }
    });

    const incomingIds = new Set(incomingProjects.map(p => p.id));
    
    // Convert map back to array and handle deletions safely
    db.projects = Array.from(existingProjectsMap.values()).filter(p => {
        if (isAdmin) {
            return incomingIds.has(p.id); // Admin syncs exact state
        } else {
            if (p.ownerId === discordId) {
                return incomingIds.has(p.id); // User can only delete their own projects
            }
            return true; // Don't delete other users' projects
        }
    });

    writeDB(db);
    res.json({ success: true });
});

// --- RAW SCRIPT URL ENDPOINT (WITH EXECUTIONS, HISTORY & WEBHOOKS) ---
app.get('/raw/:projectId/:scriptId', (req, res) => {
    const { projectId, scriptId } = req.params;
    
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
            
            // KILL SWITCH
            if (script.status !== 'Active') {
                return res.send(`print("This script is no longer working. ID: ${scriptId}")`);
            }
            
            // Increment overall executions
            script.executions = (script.executions || 0) + 1;
            
            // Increment historical daily executions (For the Dashboard Graph)
            if (!script.executionHistory) script.executionHistory = {};
            const today = new Date().toISOString().split('T'); // Format: YYYY-MM-DD
            script.executionHistory[today] = (script.executionHistory[today] || 0) + 1;
            
            writeDB(db);

            let finalLuaCode = "";

            if (project.webhookUrl && project.webhookUrl.trim() !== "") {
                const luaWebhookSnippet = `-- Luau-Auth Execution Logger
pcall(function()
    local request = http_request or syn and syn.request or request
    if not request then return end
    
    local HttpService = game:GetService("HttpService")
    local Players = game:GetService("Players")
    local UIS = game:GetService("UserInputService")
    
    local player = Players.LocalPlayer
    local executor = (getexecutorname and getexecutorname()) or (identifyexecutor and identifyexecutor()) or "Unknown"
    
    local deviceType = "Unknown"
    if UIS.TouchEnabled and not UIS.KeyboardEnabled then
        deviceType = "Mobile"
    elseif UIS.GamepadEnabled and not UIS.KeyboardEnabled then
        deviceType = "Console"
    elseif UIS.KeyboardEnabled then
        deviceType = "PC"
    end
    
    getgenv().execCount = (getgenv().execCount or 0) + 1
    
    local payload = {
        username = "Luau-Auth Logger",
        embeds = {{
            title = "Execution Log",
            color = 0x4F6CEE,
            fields = {
                { name = "User Info", value = "Name: " .. player.Name .. "\\nUserId: " .. player.UserId, inline = false },
                { name = "Script Triggered", value = "${script.name}", inline = false },
                { name = "Executor", value = executor, inline = false },
                { name = "Device", value = deviceType, inline = true },
                { name = "Executions (Session)", value = tostring(getgenv().execCount), inline = true }
            }
        }}
    }
    
    request({
        Url = "${project.webhookUrl}",
        Method = "POST",
        Headers = { ["Content-Type"] = "application/json" },
        Body = HttpService:JSONEncode(payload)
    })
end)\n\n`;
                finalLuaCode += luaWebhookSnippet;
            }

            finalLuaCode += (script.code || '-- Error: Uploaded script file was completely empty.');
            return res.send(finalLuaCode);
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
    console.log(`Luau-Auth API is successfully running on port ${PORT}`);
});
