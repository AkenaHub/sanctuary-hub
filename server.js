require('dotenv').config(); // Securely load environment variables from .env file
const express = require('express');
const path = require('path');
const fs = require('fs');
const { Client, GatewayIntentBits } = require('discord.js');

const app = express();
const port = process.env.PORT || 3000;

// --- DISCORD BOT SETUP ---
const discordClient = new Client({ 
    intents: [GatewayIntentBits.Guilds] 
});

discordClient.once('ready', () => {
    console.log(`🤖 Discord Bot logged in as ${discordClient.user.tag}`);
    // You can set the bot's status here
    discordClient.user.setActivity('over LuaKnight Hub', { type: 3 }); // Type 3 = Watching
});

// Securely log in using the token from the .env file
if (process.env.DISCORD_BOT_TOKEN && process.env.DISCORD_BOT_TOKEN !== 'your_bot_token_here') {
    discordClient.login(process.env.DISCORD_BOT_TOKEN).catch(err => {
        console.error("Discord Bot Login Failed:", err.message);
    });
} else {
    console.log("⚠️ No valid Discord Bot Token found in .env file. Bot is disabled.");
}


// --- EXPRESS SETUP ---
app.use(express.json({ limit: '50mb' }));
app.use(express.static(__dirname));

app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

const DB_FILE = 'database.json';
const MASTER_KEY = "aethel-master-key-2024"; 

// --- SECURITY INJECTION ---
const LUA_PROTECTION = 'hello skid';

// Database State
let db = {
    apiKeys: [],
    projects: {}, 
    settings: {}, 
    registrations: [] 
};

// Persistence Logic
if (fs.existsSync(DB_FILE)) {
    try {
        const raw = fs.readFileSync(DB_FILE);
        db = JSON.parse(raw);
        if (!db.apiKeys) db.apiKeys = [];
        if (!db.projects) db.projects = {};
        if (!db.settings) db.settings = {};
        if (!db.registrations) db.registrations = [];
    } catch(e) {
        console.log("Database corrupted or invalid, starting fresh.");
        saveDB();
    }
} else {
    saveDB();
}

function saveDB() {
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
    } catch (e) {
        console.error("Error saving DB:", e);
    }
}

function generateId() {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

// --- ADMIN ROUTES ---

app.post('/api/admin/generate-key', (req, res) => {
    const { duration, count } = req.body;
    const qty = parseInt(count) || 1;
    const dur = parseInt(duration);
    const generated = [];
    const now = new Date();
    
    let expiresAt;
    if (dur === 0) {
        expiresAt = new Date("9999-12-31T23:59:59.999Z").toISOString();
    } else {
        expiresAt = new Date(now.getTime() + (dur * 24 * 60 * 60 * 1000)).toISOString();
    }

    for (let i = 0; i < qty; i++) {
        const key = generateId() + generateId();
        const newKey = {
            key,
            expiresAt: expiresAt,
            duration: dur,
            usedBy: 'Unclaimed',
            createdAt: now.toISOString()
        };
        db.apiKeys.push(newKey);
        generated.push(key);
    }
    saveDB();
    res.json({ success: true, newKeys: generated, allKeys: db.apiKeys });
});

app.post('/api/admin/expire-key', (req, res) => {
    const { key } = req.body;
    const keyIndex = db.apiKeys.findIndex(k => k.key === key);
    if (keyIndex > -1) {
        const yesterday = new Date();
        yesterday.setDate(yesterday.getDate() - 1);
        db.apiKeys[keyIndex].expiresAt = yesterday.toISOString();
        saveDB();
        res.json({ success: true });
    } else {
        res.status(404).json({ error: "Key not found" });
    }
});

app.post('/api/admin/extend-key', (req, res) => {
    const { key, duration } = req.body;
    const keyIndex = db.apiKeys.findIndex(k => k.key === key);
    if (keyIndex > -1) {
        const dur = parseInt(duration);
        let expiresAt;
        if (dur === 0) {
            expiresAt = new Date("9999-12-31T23:59:59.999Z").toISOString();
        } else {
            const now = new Date();
            expiresAt = new Date(now.getTime() + (dur * 24 * 60 * 60 * 1000)).toISOString();
        }
        db.apiKeys[keyIndex].expiresAt = expiresAt;
        db.apiKeys[keyIndex].duration = dur;
        saveDB();
        res.json({ success: true });
    } else {
        res.status(404).json({ error: "Key not found" });
    }
});

app.post('/api/admin/reset-user-pin', (req, res) => {
    const { targetEmail } = req.body;
    if (db.settings[targetEmail]) {
        db.settings[targetEmail].pin = ""; 
        saveDB();
        res.json({ success: true });
    } else {
        db.settings[targetEmail] = { pin: "" };
        saveDB();
        res.json({ success: true });
    }
});

app.get('/api/admin/keys', (req, res) => res.json(db.apiKeys));

app.get('/api/admin/registrations', (req, res) => {
    const enrichedRegs = db.registrations.map(r => {
        const userSettings = db.settings[r.email] || {};
        return {
            ...r,
            username: userSettings.username || 'N/A',
            password: userSettings.password || 'N/A' 
        };
    });
    res.json(enrichedRegs);
});

// --- AUTH & USER ROUTES ---

app.get('/api/user/search', (req, res) => {
    const query = req.query.q.toLowerCase();
    if (!query) return res.json([]);

    const matches = [];
    Object.keys(db.settings).forEach(email => {
        const user = db.settings[email];
        if (user.username && user.username.toLowerCase().includes(query)) {
            matches.push({
                email: email,
                username: user.username
            });
        }
    });
    res.json(matches);
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    const userSettings = db.settings[email];

    if (!userSettings) return res.json({ success: false, error: "Account not found" });
    if (userSettings.password !== password) return res.json({ success: false, error: "Incorrect Password" });

    let role = "User";
    let expiresAt = null;

    const adminReg = db.registrations.find(r => r.email === email && r.key === "MASTER_KEY");
    if (adminReg) {
        role = "Developer Access";
        expiresAt = "9999-12-31T23:59:59.999Z";
    } else {
        const keyData = db.apiKeys.find(k => k.usedBy === email);
        if (!keyData) return res.json({ success: false, error: "No active license" });
        if (new Date() > new Date(keyData.expiresAt)) return res.json({ success: false, error: "License Expired" });
        
        role = "Developer Access";
        expiresAt = keyData.expiresAt;
    }

    res.json({ success: true, role, expiresAt, username: userSettings.username });
});

app.post('/api/auth/register', (req, res) => {
    const { email, username, password, key } = req.body;

    if (db.settings[email]) return res.json({ success: false, error: "Email already registered" });

    if (key === MASTER_KEY) {
        db.registrations.push({ email, key: "MASTER_KEY", usedDate: new Date().toISOString() });
        db.settings[email] = { username, password, twoFactor: false };
        saveDB();
        return res.json({ success: true, role: 'Developer Access', expiresAt: "9999-12-31T23:59:59.999Z" });
    }

    const keyData = db.apiKeys.find(k => k.key === key);
    if (!keyData) return res.json({ success: false, error: "Invalid Key" });
    if (keyData.usedBy !== 'Unclaimed') return res.json({ success: false, error: "Key already used" });
    if (new Date() > new Date(keyData.expiresAt)) return res.json({ success: false, error: "Key Expired" });

    keyData.usedBy = email;
    keyData.usedDate = new Date().toISOString();
    
    db.registrations.push({ email, key, usedDate: new Date().toISOString() });
    db.settings[email] = { username, password, twoFactor: false };
    
    saveDB();
    res.json({ success: true, role: 'Developer Access', expiresAt: keyData.expiresAt });
});

app.get('/api/user/data', (req, res) => {
    const email = req.query.email;
    if (!email) return res.json({ projects: [], settings: {} });

    let myProjects = db.projects[email] || [];
    myProjects.forEach(p => { 
        if(!p.owner) p.owner = email; 
        if(!p.publicId) p.publicId = generateId();
        p.files.forEach(f => {
            if(!f.publicId) f.publicId = generateId();
            if(!f.history) f.history = [];
        });
    });

    let sharedProjects = [];
    Object.keys(db.projects).forEach(ownerEmail => {
        if (ownerEmail === email) return;
        const ownerProjs = db.projects[ownerEmail];
        if (ownerProjs) {
            const shared = ownerProjs.filter(p => p.collaborators && p.collaborators.includes(email));
            shared.forEach(p => {
                if(!p.owner) p.owner = ownerEmail;
                if(!p.publicId) p.publicId = generateId(); 
            });
            sharedProjects = sharedProjects.concat(shared);
        }
    });

    res.json({
        projects: [...myProjects, ...sharedProjects],
        settings: db.settings[email] || {}
    });
});

app.post('/api/user/data', (req, res) => {
    const { email, projects, settings } = req.body;
    if (!email) return res.status(400).json({ error: "No email" });

    if (settings) {
        const existing = db.settings[email] || {};
        db.settings[email] = { ...existing, ...settings };
    }

    if (projects) {
        projects.forEach(p => {
            if (!p.publicId) p.publicId = generateId();
            p.files.forEach(f => {
                if (!f.publicId) f.publicId = generateId();
                if (!f.history) f.history = [];
            });
        });

        const owned = projects.filter(p => !p.owner || p.owner === email);
        owned.forEach(p => p.owner = email);
        db.projects[email] = owned;

        const shared = projects.filter(p => p.owner && p.owner !== email);
        shared.forEach(sharedProj => {
            const ownerEmail = sharedProj.owner;
            if (db.projects[ownerEmail]) {
                const index = db.projects[ownerEmail].findIndex(p => p.id === sharedProj.id);
                if (index !== -1) {
                    db.projects[ownerEmail][index] = sharedProj;
                }
            }
        });
    }
    
    saveDB();
    res.json({ success: true });
});

// RAW ROUTE: Inject Security & Block Browsers
app.get('/raw/:pid/:fid', (req, res) => {
    const ua = req.get('User-Agent') || "";
    const secChUa = req.get('sec-ch-ua');
    const upgradeInsecure = req.get('upgrade-insecure-requests');
    const isBrowser = secChUa || upgradeInsecure || !ua.includes("Roblox");

    if (isBrowser) {
        res.setHeader('Content-Type', 'text/plain');
        return res.status(404).send('404: Not Found');
    }

    const pid = req.params.pid;
    const fid = req.params.fid;
    let foundFile = null;
    
    const allEmails = Object.keys(db.projects);
    for (const email of allEmails) {
        const projs = db.projects[email];
        const match = projs.find(p => p.publicId === pid);
        if (match) {
            const file = match.files.find(f => f.publicId === fid);
            if (file) {
                foundFile = file;
                break;
            }
        }
    }

    if (foundFile) {
        res.setHeader('Content-Type', 'text/plain');
        if (foundFile.name.endsWith('.lua') || foundFile.name.endsWith('.txt')) {
             res.send(LUA_PROTECTION + foundFile.content);
        } else {
             res.send(foundFile.content);
        }
    } else {
        res.status(404).send('404: Not Found');
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(port, () => {
    console.log(`Server running at port ${port}`);
});
