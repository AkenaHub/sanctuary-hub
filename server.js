const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Client, GatewayIntentBits, ActionRowBuilder, ButtonBuilder, ButtonStyle, ModalBuilder, TextInputBuilder, TextInputStyle, EmbedBuilder, REST, Routes, SlashCommandBuilder, PermissionFlagsBits, StringSelectMenuBuilder } = require('discord.js');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(__dirname));

const dbPath = path.join(__dirname, 'database.json');
const ADMIN_IDS = ["1284247278957367337", "1282859051092414586"];

const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const HOST_URL = process.env.HOST_URL;
const REDIRECT_URI = `${HOST_URL}/api/auth/callback`;

const client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent] });

const EMOJI_CHECK = "\u2705";
const readDB = () => {
    try {
        if (fs.existsSync(dbPath)) {
            const data = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
            if (!data.apiKeys) data.apiKeys = {};
            if (!data.projects) data.projects = [];
            if (!data.guildConfigs) data.guildConfigs = {};
            if (!data.giveaways) data.giveaways = [];
            return data;
        }
    } catch (err) {}
    return { projects: [], apiKeys: {}, sessions: {}, guildConfigs: {}, giveaways: [] };
};

const writeDB = (data) => {
    try { fs.writeFileSync(dbPath, JSON.stringify(data, null, 2)); } catch (err) {}
};

const requireValidAccess = (req, res, next) => {
    const { apiKey, discordId } = req.body;
    if (ADMIN_IDS.includes(discordId)) return next();
    if (!apiKey) return res.status(401).json({ error: "API Key required" });
    const db = readDB();
    if (!db.apiKeys[apiKey]) return res.status(401).json({ error: "Invalid API Key" });
    if (Date.now() > db.apiKeys[apiKey].expiresAt) return res.status(403).json({ error: "API Key expired" });
    next();
};

app.get('/api/auth/discord', (req, res) => {
    res.redirect(`https://discord.com/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(HOST_URL + "/api/auth/callback")}&response_type=code&scope=identify`);
});

app.get('/api/auth/callback', async (req, res) => {
    if (!req.query.code) return res.send("No code provided.");
    try {
        const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            body: new URLSearchParams({ client_id: DISCORD_CLIENT_ID, client_secret: DISCORD_CLIENT_SECRET, grant_type: 'authorization_code', code: req.query.code, redirect_uri: HOST_URL + "/api/auth/callback" }),
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });
        const tokenData = await tokenRes.json();
        const userRes = await fetch('https://discord.com/api/users/@me', { headers: { authorization: `Bearer ${tokenData.access_token}` } });
        const userData = await userRes.json();
        
        res.send(`<script>
            localStorage.setItem('sanctuary_user', JSON.stringify({ id: "${userData.id}", username: "${userData.username}", avatar: "${userData.avatar || ''}", isAdmin: ${ADMIN_IDS.includes(userData.id)} }));
            window.location.href = "/";
        </script>`);
    } catch (err) { res.status(500).send("Auth failed."); }
});

app.post('/api/link-key', (req, res) => {
    const db = readDB();
    if (!db.apiKeys[req.body.apiKey]) return res.status(400).json({ error: "Invalid Key" });
    db.apiKeys[req.body.apiKey].userId = req.body.discordId;
    db.apiKeys[req.body.apiKey].username = req.body.discordName;
    writeDB(db);
    res.json({ success: true, expiresAt: db.apiKeys[req.body.apiKey].expiresAt });
});

app.post('/api/check-key', (req, res) => {
    const keyData = readDB().apiKeys[req.body.apiKey];
    res.json(keyData ? { valid: true, expiresAt: keyData.expiresAt } : { valid: false });
});

const requireAdmin = (req, res, next) => ADMIN_IDS.includes(req.body.discordId) ? next() : res.status(403).json({ error: "Unauthorized" });

app.post('/api/admin/keys', requireAdmin, (req, res) => res.json({ keys: readDB().apiKeys }));

app.post('/api/admin/generate-key', requireAdmin, (req, res) => {
    const db = readDB();
    const newKey = crypto.randomBytes(12).toString('hex').toLowerCase();
    const expiresAt = Date.now() + (parseInt(req.body.days) * 24 * 60 * 60 * 1000);
    db.apiKeys[newKey] = { createdAt: Date.now(), expiresAt, userId: null, username: null };
    writeDB(db);
    res.json({ key: newKey, expiresAt });
});

app.post('/api/admin/extend-key', requireAdmin, (req, res) => {
    const db = readDB();
    if (!db.apiKeys[req.body.targetKey]) return res.status(404).json({ error: "Not found" });
    db.apiKeys[req.body.targetKey].expiresAt += (parseInt(req.body.days) * 24 * 60 * 60 * 1000);
    writeDB(db);
    res.json({ success: true });
});

app.post('/api/admin/revoke-key', requireAdmin, (req, res) => {
    const db = readDB();
    delete db.apiKeys[req.body.targetKey];
    writeDB(db);
    res.json({ success: true });
});

app.get('/api/sync', (req, res) => {
    const db = readDB();
    const dId = req.query.discordId;
    if (!dId) return res.json({ projects: [] });
    db.projects.forEach(p => { p.ownerId = p.ownerId || dId; p.freeMode = p.freeMode ?? true; p.hwidResetCooldown = p.hwidResetCooldown ?? 24; p.hwidKeys = p.hwidKeys || []; });
    writeDB(db);
    res.json({ projects: ADMIN_IDS.includes(dId) ? db.projects : db.projects.filter(p => p.ownerId === dId) });
});

app.post('/api/sync', requireValidAccess, (req, res) => {
    const db = readDB();
    if (ADMIN_IDS.includes(req.body.discordId)) {
        db.projects = req.body.projects;
    } else {
        const others = db.projects.filter(p => p.ownerId !== req.body.discordId);
        req.body.projects.forEach(p => p.ownerId = req.body.discordId);
        db.projects = [...others, ...req.body.projects];
    }
    writeDB(db);
    res.json({ success: true });
});

app.get('/raw/:projectId/:scriptId', (req, res) => {
    const db = readDB();
    const project = db.projects.find(p => p.id === req.params.projectId);
    if (!project) return res.status(404).send(`print("Project not found")`);
    const script = project.scripts.find(s => s.id === req.params.scriptId);
    if (!script) return res.status(404).send(`print("Script not found")`);
    if (script.status !== 'Active') return res.send(`print("This script is inactive.")`);

    let currentIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || "UNKNOWN";
    if (currentIp.includes(',')) currentIp = currentIp.split(',').trim();

    let lua = `local v0 = (getexecutorname and getexecutorname()) or ""\nlocal v1 = ${script.allowSolaraXeno ? "true" : "false"}\npcall(function() if not v1 and (v0:lower():find("xeno") or v0:lower():find("solara")) then game:GetService("Players").LocalPlayer:Kick("Executor not supported.") end end)\n\n`;

    if (project.freeMode === false) {
        const { key, hwid } = req.query;
        if (!key) return res.send(`game:GetService("Players").LocalPlayer:Kick("Sanctuary: No Script Key Provided")`);
        const hwidKey = (project.hwidKeys || []).find(k => k.key === key);
        if (!hwidKey || hwidKey.expiresAt < Date.now()) return res.send(`game:GetService("Players").LocalPlayer:Kick("Sanctuary: Invalid or expired key")`);
        
        if (!hwidKey.hwid) {
            hwidKey.hwid = hwid || "UNKNOWN";
            hwidKey.ip = currentIp;
            writeDB(db);
        } else if (hwidKey.hwid !== hwid && hwid) {
            return res.send(`game:GetService("Players").LocalPlayer:Kick("Sanctuary: Invalid HWID.")`);
        }

        lua += `local _k = getgenv().script_key\nif not _k or _k ~= "${key}" then game:GetService("Players").LocalPlayer:Kick("Sanctuary: Invalid Key") return end\n\n`;
    }
    
    script.executions = (script.executions || 0) + 1;
    script.executionHistory = script.executionHistory || {};
    const today = new Date().toISOString().split('T');
    script.executionHistory[today] = (script.executionHistory[today] || 0) + 1;
    writeDB(db);

    if (project.webhookUrl) {
        lua += `pcall(function() local r = http_request or syn and syn.request or request; if r then r({Url="${project.webhookUrl}", Method="POST", Headers={["Content-Type"]="application/json"}, Body=game:GetService("HttpService"):JSONEncode({username="Sanctuary Logger", content="Executed: ${script.name} by " .. game.Players.LocalPlayer.Name})}) end end)\n\n`;
    }
    res.type('text/plain').send(lua + (script.code || ""));
});

app.get('/loader/:projectId', (req, res) => {
    const p = readDB().projects.find(p => p.id === req.params.projectId);
    if (!p) return res.status(404).send(`print("Project not found")`);
    let table = (p.scripts || []).map(s => `["${s.gameId || 'Universal'}"] = "${HOST_URL}/raw/${p.id}/${s.id}"`).join(",\n    ");
    let lua = `local Scripts = {\n    ${table}\n}\nlocal Script = Scripts[tostring(game.GameId)] or Scripts[game.GameId] or Scripts["Universal"]\nif Script then\n`;
    lua += p.freeMode === false ? `    local k = getgenv().script_key or ""\n    local h = ((gethwid and gethwid()) or "nohwid") .. "_" .. game:GetService("RbxAnalyticsService"):GetClientId()\n    loadstring(game:HttpGet(Script .. "?key=" .. k .. "&hwid=" .. h))()\n` : `    loadstring(game:HttpGet(Script))()\n`;
    res.type('text/plain').send(lua + `else warn("Sanctuary: No valid script.") end`);
});

const cmds = [];

const cmdLogin = new SlashCommandBuilder()
    .setName('login')
    .setDescription('Link your API Key to your Discord account')
    .addStringOption(opt => opt.setName('api_key').setDescription('Your Sanctuary API Key').setRequired(true));
cmds.push(cmdLogin);

const otherCmds = ['set_admin_role', 'setup_panel', 'create_giveaway', 'generate_key', 'clear_keys', 'user_info', 'reset_hwid', 'extend_key', 'revoke_key'];
for (const name of otherCmds) {
    cmds.push(new SlashCommandBuilder().setName(name).setDescription(`Execute ${name}`));
}

client.once('ready', async () => {
    try { await new REST({ version: '10' }).setToken(DISCORD_BOT_TOKEN).put(Routes.applicationCommands(client.user.id), { body: cmds.map(c => c.toJSON()) }); console.log("✅ Commands Registered"); } catch (e) {}
});

client.on('interactionCreate', async i => {
    try {
        const db = readDB();
        if (i.isCommand()) {
            if (i.commandName === 'setup_panel') {
                const row = new ActionRowBuilder().addComponents(new StringSelectMenuBuilder().setCustomId("selectproj_setuppanel").setPlaceholder('Select Project').addOptions(db.projects.filter(p => ADMIN_IDS.includes(i.user.id) || p.ownerId === i.user.id).slice(0, 25).map(p => ({label: p.name, value: p.id}))));
                return i.reply({ content: "Select a project:", components: [row], ephemeral: true });
            }
            if (i.commandName === 'generate_key') {
                const modal = new ModalBuilder().setCustomId("modal_genkey").setTitle('Generate Keys');
                modal.addComponents(new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('days').setLabel("Days").setStyle(TextInputStyle.Short)), new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('amount').setLabel("Amount").setStyle(TextInputStyle.Short)));
                return await i.showModal(modal);
            }
            return i.reply({ content: "Command available in Dashboard UI.", ephemeral: true });
        }
        if (i.isStringSelectMenu() && i.customId === 'selectproj_setuppanel') {
            const p = db.projects.find(p => p.id === i.values);
            const e = new EmbedBuilder().setTitle(`${p.name} - Script Panel`).setColor(0x4F6CEE).setDescription("• Redeem your key\n• Get the script\n• Reset your HWID");
            const r1 = new ActionRowBuilder().addComponents(new ButtonBuilder().setCustomId(`auth_redeem_${p.id}`).setLabel('Redeem Key').setStyle(ButtonStyle.Success), new ButtonBuilder().setCustomId(`auth_getscriptnoembed_${p.id}`).setLabel('Get Script').setStyle(ButtonStyle.Primary), new ButtonBuilder().setCustomId(`auth_reset_${p.id}`).setLabel('Reset HWID').setStyle(ButtonStyle.Danger));
            await client.channels.cache.get(i.channelId).send({ embeds: [e], components: [r1] });
            return i.reply({ content: "✅ Deployed.", ephemeral: true });
        }
        if (i.isButton()) {
            const pId = i.customId.split('_');
            const p = db.projects.find(p => p.id === pId);
            if (i.customId.startsWith('auth_redeem_')) {
                const m = new ModalBuilder().setCustomId(`modal_redeem_${pId}`).setTitle('Redeem Key');
                m.addComponents(new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('keyInput').setLabel("Key").setStyle(TextInputStyle.Short)));
                return await i.showModal(m);
            }
            if (i.customId.startsWith('auth_getscript')) {
                const k = (p.hwidKeys || []).find(k => k.userId === i.user.id);
                if (!k) return i.reply({ content: "You do not own a key.", ephemeral: true });
                return i.reply({ content: `getgenv().script_key = "${k.key}"\nloadstring(game:HttpGet("${HOST_URL}/loader/${pId}"))()`, ephemeral: true });
            }
            if (i.customId.startsWith('auth_reset')) {
                const k = (p.hwidKeys || []).find(k => k.userId === i.user.id);
                if (!k) return i.reply({ content: "You do not own a key.", ephemeral: true });
                k.hwid = null; k.ip = null; writeDB(db);
                return i.reply({ content: "✅ HWID Reset.", ephemeral: true });
            }
        }
        if (i.isModalSubmit()) {
            if (i.customId.startsWith('modal_redeem_')) {
                const k = (db.projects.find(p => p.id === i.customId.split('_')).hwidKeys || []).find(x => x.key === i.fields.getTextInputValue('keyInput'));
                if (!k || k.userId) return i.reply({ content: "Invalid or claimed key.", ephemeral: true });
                k.userId = i.user.id; writeDB(db);
                return i.reply({ content: "✅ Redeemed!", ephemeral: true });
            }
        }
    } catch (e) { console.error(e); }
});

app.listen(process.env.PORT || 3000, () => console.log("Server running"));
if (DISCORD_BOT_TOKEN) client.login(DISCORD_BOT_TOKEN);
