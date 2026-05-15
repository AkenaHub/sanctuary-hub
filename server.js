console.log("Starting Sanctuary Backend...");

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Client, GatewayIntentBits, ActionRowBuilder, ButtonBuilder, ButtonStyle, ModalBuilder, TextInputBuilder, TextInputStyle, EmbedBuilder, REST, Routes, SlashCommandBuilder, AttachmentBuilder, PermissionFlagsBits, StringSelectMenuBuilder } = require('discord.js');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(__dirname));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

const dbPath = path.join(__dirname, 'database.json');
const ADMIN_IDS = ["1284247278957367337", "1282859051092414586"];

// Secure Environment Variables (Set these in Railway)
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const HOST_URL = process.env.HOST_URL;
const REDIRECT_URI = `${HOST_URL}/api/auth/callback`;

// Safe Unicode Emojis
const EMOJI_CHECK = "\u2705";
const EMOJI_CROSS = "\u274C";
const EMOJI_TADA = "\uD83C\uDF89";
const EMOJI_SAD = "\uD83D\uDE22";
const EMOJI_BROOM = "\uD83E\uDDF9";
const EMOJI_TRASH = "\uD83D\uDDD1\uFE0F";

const client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent] });

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
    const keyData = db.apiKeys[apiKey];
    if (!keyData) return res.status(401).json({ error: "Invalid API Key" });
    if (Date.now() > keyData.expiresAt) return res.status(403).json({ error: "API Key expired" });
    next();
};

app.get('/api/auth/discord', (req, res) => {
    if (!DISCORD_CLIENT_ID || !HOST_URL) return res.status(500).send("Railway Variables not configured.");
    res.redirect(`https://discord.com/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=identify`);
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
        
        const safeUserObj = {
            id: userData.id,
            username: userData.username,
            avatar: userData.avatar || '',
            isAdmin: ADMIN_IDS.includes(userData.id)
        };
        
        const htmlResponse = `
            <script>
                localStorage.setItem('sanctuary_user', JSON.stringify(${JSON.stringify(safeUserObj)}));
                window.location.href = "/";
            </script>
        `;
        res.send(htmlResponse);
    } catch (err) {
        res.status(500).send("Authentication failed.");
    }
});

app.post('/api/link-key', (req, res) => {
    const { apiKey, discordId, discordName } = req.body;
    const db = readDB();
    if (!db.apiKeys[apiKey]) return res.status(400).json({ error: "Invalid Key" });
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

const requireAdmin = (req, res, next) => {
    if (!ADMIN_IDS.includes(req.body.discordId)) return res.status(403).json({ error: "Unauthorized" });
    next();
};

app.post('/api/admin/keys', requireAdmin, (req, res) => res.json({ keys: readDB().apiKeys }));

app.post('/api/admin/generate-key', requireAdmin, (req, res) => {
    const db = readDB();
    const newKey = crypto.randomBytes(12).toString('hex').toLowerCase();
    const expiresAt = Date.now() + (parseInt(req.body.days) * 24 * 60 * 60 * 1000);
    db.apiKeys[newKey] = { createdAt: Date.now(), expiresAt: expiresAt, userId: null, username: null };
    writeDB(db);
    res.json({ key: newKey, expiresAt: expiresAt });
});

app.post('/api/admin/extend-key', requireAdmin, (req, res) => {
    const { targetKey, days } = req.body;
    const db = readDB();
    if (!db.apiKeys[targetKey]) return res.status(404).json({ error: "Not found" });
    db.apiKeys[targetKey].expiresAt += (parseInt(days) * 24 * 60 * 60 * 1000);
    writeDB(db);
    res.json({ success: true });
});

app.post('/api/admin/revoke-key', requireAdmin, (req, res) => {
    const db = readDB();
    if (db.apiKeys[req.body.targetKey]) {
        delete db.apiKeys[req.body.targetKey];
        writeDB(db);
    }
    res.json({ success: true });
});

app.get('/api/sync', (req, res) => {
    const { discordId } = req.query;
    const db = readDB();
    if (!discordId) return res.json({ projects: [] });
    const isAdmin = ADMIN_IDS.includes(discordId);
    let needsSave = false;
    db.projects.forEach(p => {
        if (!p.ownerId) { p.ownerId = discordId; needsSave = true; }
        if (p.freeMode === undefined) { p.freeMode = true; needsSave = true; }
        if (p.hwidResetCooldown === undefined) { p.hwidResetCooldown = 24; needsSave = true; }
        if (!p.hwidKeys) { p.hwidKeys = []; needsSave = true; }
    });
    if (needsSave) writeDB(db);
    res.json({ projects: isAdmin ? db.projects : db.projects.filter(p => p.ownerId === discordId) });
});

app.post('/api/sync', requireValidAccess, (req, res) => {
    const db = readDB();
    const incomingProjects = req.body.projects;
    const discordId = req.body.discordId;
    const isAdmin = ADMIN_IDS.includes(discordId);
    if (isAdmin) {
        db.projects = incomingProjects;
    } else {
        const otherUsersProjects = db.projects.filter(p => p.ownerId !== discordId);
        const userProjectsToSave = incomingProjects.filter(p => p.ownerId === discordId || !p.ownerId);
        userProjectsToSave.forEach(p => p.ownerId = discordId);
        db.projects = [...otherUsersProjects, ...userProjectsToSave];
    }
    writeDB(db);
    res.json({ success: true });
});

app.get('/raw/:projectId/:scriptId', async (req, res) => {
    const { projectId, scriptId } = req.params;
    const { key, hwid } = req.query;
    const acceptHeader = req.headers['accept'] || "";
    
    if (acceptHeader.includes("text/html")) {
        res.type('text/plain');
        return res.send(`print("Script ID: ${scriptId}")`);
    }
    
    const db = readDB();
    const project = db.projects.find(p => p.id === projectId);
    
    let currentIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || "UNKNOWN";
    if (typeof currentIp === 'string' && currentIp.includes(',')) {
        currentIp = currentIp.split(',').shift().trim();
    }

    if (project) {
        const script = project.scripts.find(s => s.id === scriptId);
        if (script) {
            res.type('text/plain');
            if (script.status !== 'Active') {
                return res.send(`print("This script is no longer working.")`);
            }
            
            let finalLuaCode = `
local v0 = (getexecutorname and getexecutorname()) or ""
local v1 = ${script.allowSolaraXeno === true ? "true" : "false"}
local v2 = function()
    print("Running Sanctuary Engine...")
    pcall(function()
        if not v1 then
            if v0 and (v0:lower():find("xeno") or v0:lower():find("solara")) then
                game:GetService("Players").LocalPlayer:Kick("You are using an executor that doesn't support this script.\\nExecutor: [" .. v0 .. "]\\nPlease use another executor.")
            else
                if v0 ~= nil and v0 ~= "" then
                    print("Executor:" .. v0)
                    print("Valid Executor.")
                end
            end
        end
    end)
end
v2()

`;

            if (project.freeMode === false) {
                if (!key) return res.send(`game:GetService("Players").LocalPlayer:Kick("Sanctuary: No Script Key Provided")`);
                const hwidKey = (project.hwidKeys || []).find(k => k.key === key);
                if (!hwidKey || hwidKey.expiresAt < Date.now()) {
                    return res.send(`game:GetService("Players").LocalPlayer:Kick("Sanctuary: Invalid or expired key")`);
                }
                if (!hwidKey.hwid) {
                    hwidKey.hwid = hwid || "UNKNOWN";
                    hwidKey.ip = currentIp;
                    writeDB(db);
                } else {
                    if (hwidKey.hwid !== hwid && hwid) {
                        return res.send(`game:GetService("Players").LocalPlayer:Kick("Sanctuary: Invalid HWID. Key is locked to another device.")`);
                    }
                    if (hwidKey.ip && hwidKey.ip !== currentIp && currentIp !== "UNKNOWN") {
                        return res.send(`game:GetService("Players").LocalPlayer:Kick("Sanctuary: Invalid IP Address. Key is locked to another network.")`);
                    }
                }
                if (project.discordConfig && project.discordConfig.roleId && hwidKey.userId) {
                    try {
                        const guild = await client.guilds.fetch(project.discordConfig.guildId);
                        const member = await guild.members.fetch(hwidKey.userId);
                        if (!member.roles.cache.has(project.discordConfig.roleId)) {
                            return res.send(`game:GetService("Players").LocalPlayer:Kick("Sanctuary: Missing Discord Role")`);
                        }
                    } catch (err) {
                        return res.send(`game:GetService("Players").LocalPlayer:Kick("Sanctuary: Discord Authentication Error")`);
                    }
                }

                finalLuaCode += `
local _authKey = getgenv().script_key
local _authHwid1 = (gethwid and gethwid()) or "nohwid"
local _authHwid2 = game:GetService("RbxAnalyticsService"):GetClientId()
local _authHwid = _authHwid1 .. "_" .. _authHwid2
if not _authKey or _authKey == "" then
    game:GetService("Players").LocalPlayer:Kick("Sanctuary: Whitelist Error - No Key Provided")
    return
end
if _authKey ~= "${key}" then
    game:GetService("Players").LocalPlayer:Kick("Sanctuary: Whitelist Error - Key Mismatch")
    return
end\n\n`;
            }
            
            script.executions = (script.executions || 0) + 1;
            if (!script.executionHistory) script.executionHistory = {};
            const today = new Date().toISOString().split('T').shift();
            script.executionHistory[today] = (script.executionHistory[today] || 0) + 1;
            writeDB(db);
            
            if (project.webhookUrl && project.webhookUrl.trim() !== "") {
                finalLuaCode += `
pcall(function()
    local request = http_request or syn and syn.request or request
    if not request then return end
    local HttpService = game:GetService("HttpService")
    local Players = game:GetService("Players")
    local UIS = game:GetService("UserInputService")
    local player = Players.LocalPlayer
    local executor = (getexecutorname and getexecutorname()) or (identifyexecutor and identifyexecutor()) or "Unknown"
    local deviceType = "Unknown"
    if UIS.TouchEnabled and not UIS.KeyboardEnabled then deviceType = "Mobile"
    elseif UIS.GamepadEnabled and not UIS.KeyboardEnabled then deviceType = "Console"
    elseif UIS.KeyboardEnabled then deviceType = "PC" end
    getgenv().execCount = (getgenv().execCount or 0) + 1
    local payload = {
        username = "Sanctuary Logger",
        embeds = {{
            title = "Execution Log",
            color = 0x4F6CEE,
            fields = {
                { name = "User Info", value = "Name: " .. player.Name .. "\\nUserId: " .. player.UserId, inline = false },
                { name = "Script Triggered", value = "${script.name}", inline = false },
                { name = "Executor", value = executor, inline = false },
                { name = "Device", value = deviceType, inline = true },
                { name = "IP Address", value = "${currentIp}", inline = true },
                { name = "Executions", value = tostring(getgenv().execCount), inline = true }
            }
        }}
    }
    request({ Url = "${project.webhookUrl}", Method = "POST", Headers = { ["Content-Type"] = "application/json" }, Body = HttpService:JSONEncode(payload) })
end)\n\n`;
            }
            return res.send(finalLuaCode + (script.code || `print("Empty script")`));
        }
    }
    res.status(404).send(`print("Error: Script or Project not found")`);
});

app.get('/loader/:projectId', (req, res) => {
    const project = readDB().projects.find(p => p.id === req.params.projectId);
    if (project) {
        res.type('text/plain');
        let scriptsTable = "";
        (project.scripts || []).forEach(s => {
            if (s.gameId && s.gameId !== "") {
                scriptsTable += `    ["${s.gameId}"] = "${HOST_URL}/raw/${project.id}/${s.id}",\n`;
            } else {
                scriptsTable += `    ["Universal"] = "${HOST_URL}/raw/${project.id}/${s.id}",\n`;
            }
        });
        
        let authSnippet = "";
        let callSnippet = `loadstring(game:HttpGet(Script))()`;

        if (project.freeMode === false) {
            authSnippet = `\nlocal AuthKey = getgenv().script_key or ""\nlocal hw1 = (gethwid and gethwid()) or "nohwid"\nlocal hw2 = game:GetService("RbxAnalyticsService"):GetClientId()\nlocal hwid = hw1 .. "_" .. hw2\n`;
            callSnippet = `loadstring(game:HttpGet(Script .. "?key=" .. AuthKey .. "&hwid=" .. hwid))()`;
        }
        
        let dynamicLoader = `local ProjectId = "${project.id}"\n`;
        dynamicLoader += `local Scripts = {\n${scriptsTable}}\n`;
        dynamicLoader += `local Script = Scripts[tostring(game.GameId)] or Scripts[game.GameId] or Scripts["Universal"]\n`;
        dynamicLoader += `if Script then${authSnippet}\n    ${callSnippet}\nelse\n    warn("Sanctuary: No valid script found for this game.")\nend`;
        
        return res.send(dynamicLoader);
    }
    res.status(404).send(`print("Error: Project not found")`);
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
    if (!DISCORD_BOT_TOKEN) {
        console.log("❌ DISCORD_BOT_TOKEN is missing in Railway Variables!");
        return;
    }
    const rest = new REST({ version: '10' }).setToken(DISCORD_BOT_TOKEN);
    try {
        const cmdJson = cmds.map(c => c.toJSON());
        await rest.put(Routes.applicationCommands(client.user.id), { body: cmdJson });
        console.log("✅ Slash commands fully registered.");
    } catch (error) {
        console.log("❌ Failed to register commands:", error);
    }
});

client.on('messageCreate', async message => {
    if (message.author.bot || !message.guild) return;
    if (message.member && message.member.permissions.has(PermissionFlagsBits.Administrator)) return;
    if (ADMIN_IDS.includes(message.author.id)) return;

    const content = message.content.toLowerCase();
    const inviteRegex = /(discord\.(gg|com\/invite)\/|dsc\.gg\/|invite\.gg\/)/i;
    const promoRegex = /(youtube\.com\/(c|channel)\/|twitch\.tv\/|onlyfans\.com\/|tiktok\.com\/@|twitter\.com\/)/i;
    
    if (inviteRegex.test(content) || promoRegex.test(content)) {
        await message.delete().catch(() => {});
        const warnMsg = await message.channel.send(`<@${message.author.id}>, posting invites or self-promotion is not allowed!`);
        setTimeout(() => warnMsg.delete().catch(() => {}), 5000);
        return;
    }

    if (message.mentions.users.size > 4) {
        await message.delete().catch(() => {});
        const warnMsg = await message.channel.send(`<@${message.author.id}>, please do not mass-mention users.`);
        setTimeout(() => warnMsg.delete().catch(() => {}), 5000);
        return;
    }
});

setInterval(async () => {
    const db = readDB();
    let needsSave = false;
    
    for (let p of db.projects) {
        if (!p.hwidKeys) continue;
        for (let k of p.hwidKeys) {
            if (k.userId && Date.now() > k.expiresAt && !k.roleRemoved) {
                if (p.discordConfig && p.discordConfig.roleId) {
                    try {
                        const guild = await client.guilds.fetch(p.discordConfig.guildId);
                        const member = await guild.members.fetch(k.userId);
                        await member.roles.remove(p.discordConfig.roleId);
                    } catch (err) {}
                }
                k.roleRemoved = true;
                needsSave = true;
            }
        }
    }

    for (let gw of db.giveaways) {
        if (!gw.ended && Date.now() >= gw.endsAt) {
            gw.ended = true;
            needsSave = true;

            const project = db.projects.find(p => p.id === gw.projectId);
            if (!project) continue;

            try {
                const channel = await client.channels.fetch(gw.channelId).catch(() => null);
                if (!channel) continue;

                if (!gw.participants || gw.participants.length === 0) {
                    const failEmbed = new EmbedBuilder()
                        .setTitle(`${EMOJI_TADA} **Giveaway Ended** ${EMOJI_TADA}`)
                        .setColor(0x3f3f46)
                        .setDescription(`Nobody entered the giveaway for **${project.name}**. ${EMOJI_SAD}`);
                    await channel.send({ embeds: [failEmbed] }).catch(() => {});
                } else {
                    const shuffled = gw.participants.sort(() => 0.5 - Math.random());
                    const winners = shuffled.slice(0, gw.winnersCount);

                    const winnerMentions = [];
                    const expiresAt = Date.now() + (gw.keyDays * 24 * 60 * 60 * 1000);
                    
                    for (let wId of winners) {
                        winnerMentions.push(`<@${wId}>`);
                        const newKey = crypto.randomBytes(12).toString('hex').toLowerCase();
                        
                        if (!project.hwidKeys) project.hwidKeys = [];
                        project.hwidKeys.push({
                            key: newKey,
                            note: "Giveaway Winner",
                            createdAt: Date.now(),
                            expiresAt: expiresAt,
                            userId: wId,
                            hwid: null,
                            ip: null,
                            roleRemoved: false
                        });

                        if (project.discordConfig && project.discordConfig.roleId) {
                            try {
                                const guild = await client.guilds.fetch(gw.guildId);
                                const member = await guild.members.fetch(wId);
                                await member.roles.add(project.discordConfig.roleId);
                            } catch(e) {}
                        }

                        try {
                            const user = await client.users.fetch(wId);
                            const loaderCode = `getgenv().script_key = "${newKey}"\nloadstring(game:HttpGet("${HOST_URL}/loader/${project.id}"))()`;
                            const dmEmbed = new EmbedBuilder()
                                .setTitle(`${EMOJI_TADA} You won the Giveaway!`)
                                .setColor(0x4F6CEE)
                                .setDescription(`Congratulations! You won a **${gw.keyDays} Day** key for **${project.name}**!\n\nYour key has automatically been redeemed to your Discord account, and you have been given the customer role.\n\n**Your Script Loader:**\n\`\`\`lua\n${loaderCode}\n\`\`\``);
                            await user.send({ embeds: [dmEmbed] }).catch(() => {});
                        } catch(e) {}
                    }

                    const winEmbed = new EmbedBuilder()
                        .setTitle(`${EMOJI_TADA} **Giveaway Winners!** ${EMOJI_TADA}`)
                        .setColor(0x10b981)
                        .setDescription(`**Prize:** ${gw.winnersCount}x Key(s) for ${project.name}\n**Winners:** ${winnerMentions.join(', ')}\n\n*Winners have been given the customer role and DMed their scripts automatically!*`);
                    
                    await channel.send({ embeds: [winEmbed] }).catch(() => {});
                }

                try {
                    const msg = await channel.messages.fetch(gw.messageId);
                    const endedRow = new ActionRowBuilder().addComponents(
                        new ButtonBuilder().setCustomId('ended_btn').setLabel('Giveaway Ended').setStyle(ButtonStyle.Secondary).setDisabled(true)
                    );
                    await msg.edit({ components: [endedRow] });
                } catch(e) {}

            } catch (e) {}
        }
    }

    if (needsSave) writeDB(db);
}, 15 * 1000);

const buildProjectSelect = (customId, interaction, db) => {
    const isGlobalAdmin = ADMIN_IDS.includes(interaction.user.id);
    const userProjects = isGlobalAdmin ? db.projects : db.projects.filter(p => p.ownerId === interaction.user.id);
    
    if (userProjects.length === 0) return null;

    const options = userProjects.map(p => ({
        label: p.name,
        description: `Project ID: ${p.id.substring(0, 20)}...`,
        value: p.id
    })).slice(0, 25);

    const selectMenu = new StringSelectMenuBuilder()
        .setCustomId(customId)
        .setPlaceholder('Select a project')
        .addOptions(options);

    return new ActionRowBuilder().addComponents(selectMenu);
};

client.on('interactionCreate', async interaction => {
    try {
        if (interaction.isCommand()) {
            if (!interaction.guild) return interaction.reply({ content: "Commands must be used in a server.", ephemeral: true });

            const db = readDB();

            if (interaction.commandName === 'login') {
                const apiKey = interaction.options.getString('api_key');
                if (!db.apiKeys[apiKey]) {
                    const errEmbed = new EmbedBuilder().setColor(0xEF4444).setDescription(`${EMOJI_CROSS} Invalid API Key.`);
                    return interaction.reply({ embeds: [errEmbed], ephemeral: true });
                }
                if (Date.now() > db.apiKeys[apiKey].expiresAt) {
                    const errEmbed = new EmbedBuilder().setColor(0xEF4444).setDescription(`${EMOJI_CROSS} API Key is expired.`);
                    return interaction.reply({ embeds: [errEmbed], ephemeral: true });
                }

                db.apiKeys[apiKey].userId = interaction.user.id;
                db.apiKeys[apiKey].username = interaction.user.username;
                writeDB(db);

                const okEmbed = new EmbedBuilder()
                    .setColor(0x10B981)
                    .setTitle(`${EMOJI_CHECK} Successfully Logged In`)
                    .setDescription("Your Discord account is now securely linked to this API Key. You can now use bot commands.");
                return interaction.reply({ embeds: [okEmbed], ephemeral: true });
            }

            const isGlobalAdmin = ADMIN_IDS.includes(interaction.user.id);
            const isServerOwner = interaction.user.id === interaction.guild.ownerId;
            
            let hasLinkedApiKey = false;
            for (let k in db.apiKeys) {
                if (db.apiKeys[k].userId === interaction.user.id && Date.now() < db.apiKeys[k].expiresAt) {
                    hasLinkedApiKey = true;
                    break;
                }
            }

            let hasAdminRole = false;
            if (interaction.guildId && db.guildConfigs && db.guildConfigs[interaction.guildId]) {
                const adminRoleId = db.guildConfigs[interaction.guildId].adminRoleId;
                if (adminRoleId) {
                    try {
                        const member = await interaction.guild.members.fetch(interaction.user.id);
                        if (member.roles.cache.has(adminRoleId)) hasAdminRole = true;
                    } catch(e){}
                }
            }
            
            const isAuthorized = isGlobalAdmin || isServerOwner || (hasAdminRole && hasLinkedApiKey);

            if (interaction.commandName === 'set_admin_role') {
                if (!isGlobalAdmin && !isServerOwner) {
                    const errEmbed = new EmbedBuilder().setColor(0xEF4444).setDescription(`${EMOJI_CROSS} Only the Server Owner or Global Admin can assign the Admin Role.`);
                    return interaction.reply({ embeds: [errEmbed], ephemeral: true });
                }
                const modal = new ModalBuilder().setCustomId("modal_setadminrole").setTitle('Set Admin Role');
                modal.addComponents(new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('roleId').setLabel("Discord Role ID").setStyle(TextInputStyle.Short).setRequired(true)));
                return await interaction.showModal(modal).catch(console.error);
            }
            
            if (!isAuthorized) {
                const errEmbed = new EmbedBuilder()
                    .setColor(0xEF4444)
                    .setTitle(`${EMOJI_CROSS} Unauthorized`)
                    .setDescription("You must be the **Server Owner**, or have the designated **Admin Role** with a valid linked **API Key** (`/login`) to use this command.");
                return interaction.reply({ embeds: [errEmbed], ephemeral: true });
            }

            if (interaction.commandName === 'setup_panel') {
                const row = buildProjectSelect("selectproj_setuppanel", interaction, db);
                if (!row) return interaction.reply({ content: "You don't have any projects.", ephemeral: true });
                return interaction.reply({ content: "Please select a project for the panel:", components: [row], ephemeral: true });
            }

            if (interaction.commandName === 'create_giveaway') {
                const row = buildProjectSelect("selectproj_giveaway", interaction, db);
                if (!row) return interaction.reply({ content: "You don't have any projects.", ephemeral: true });
                return interaction.reply({ content: "Please select a project for the giveaway:", components: [row], ephemeral: true });
            }

            if (interaction.commandName === 'generate_key') {
                const row = buildProjectSelect("selectproj_genkey", interaction, db);
                if (!row) return interaction.reply({ content: "You don't have any projects.", ephemeral: true });
                return interaction.reply({ content: "Please select a project to generate keys for:", components: [row], ephemeral: true });
            }

            if (interaction.commandName === 'clear_keys') {
                const row = buildProjectSelect("selectproj_clearkeys", interaction, db);
                if (!row) return interaction.reply({ content: "You don't have any projects.", ephemeral: true });
                return interaction.reply({ content: "Please select a project to clear keys from:", components: [row], ephemeral: true });
            }

            if (interaction.commandName === 'user_info') {
                const row = buildProjectSelect("selectproj_userinfo", interaction, db);
                if (!row) return interaction.reply({ content: "You don't have any projects.", ephemeral: true });
                return interaction.reply({ content: "Please select a project to view the user's info:", components: [row], ephemeral: true });
            }

            if (interaction.commandName === 'reset_hwid') {
                const modal = new ModalBuilder().setCustomId("modal_resethwid").setTitle('Reset User HWID');
                modal.addComponents(new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('hwidKey').setLabel("The HWID Key").setStyle(TextInputStyle.Short).setRequired(true)));
                return await interaction.showModal(modal).catch(console.error);
            }

            if (interaction.commandName === 'extend_key') {
                const modal = new ModalBuilder().setCustomId("modal_extendkey").setTitle('Extend User Key');
                modal.addComponents(
                    new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('hwidKey').setLabel("The HWID Key").setStyle(TextInputStyle.Short).setRequired(true)),
                    new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('days').setLabel("Days to Add").setStyle(TextInputStyle.Short).setRequired(true))
                );
                return await interaction.showModal(modal).catch(console.error);
            }

            if (interaction.commandName === 'revoke_key') {
                const modal = new ModalBuilder().setCustomId("modal_revokekey").setTitle('Revoke User Key');
                modal.addComponents(new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('hwidKey').setLabel("The HWID Key to delete").setStyle(TextInputStyle.Short).setRequired(true)));
                return await interaction.showModal(modal).catch(console.error);
            }
        }

        if (interaction.isStringSelectMenu()) {
            const parts = interaction.customId.split('_');
            const prefix = parts;
            
            if (prefix === 'selectproj') {
                const action = parts;
                const projectId = interaction.values;
                const db = readDB();
                const project = db.projects.find(p => p.id === projectId);

                if (!project) return interaction.update({ content: "Project not found.", components: [] });

                if (action === 'setuppanel') {
                    try {
                        const modal = new ModalBuilder().setCustomId(`modal_setuppanel_${projectId}`).setTitle('Setup Panel Settings');
                        modal.addComponents(new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('roleId').setLabel("Customer Role ID (Optional)").setStyle(TextInputStyle.Short).setRequired(false)));
                        return await interaction.showModal(modal);
                    } catch (e) { console.error(e); }
                }

                if (action === 'giveaway') {
                    try {
                        const modal = new ModalBuilder().setCustomId(`modal_giveaway_${projectId}`).setTitle('Giveaway Settings');
                        modal.addComponents(
                            new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('winners').setLabel("Number of Winners").setStyle(TextInputStyle.Short).setRequired(true)),
                            new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('keyDays').setLabel("Key Duration (Days)").setStyle(TextInputStyle.Short).setRequired(true)),
                            new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('durationMins').setLabel("Giveaway Duration (Minutes)").setStyle(TextInputStyle.Short).setRequired(true))
                        );
                        return await interaction.showModal(modal);
                    } catch (e) { console.error(e); }
                }

                if (action === 'genkey') {
                    try {
                        const modal = new ModalBuilder().setCustomId(`modal_genkey_${projectId}`).setTitle('Generate Keys');
                        modal.addComponents(
                            new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('days').setLabel("Duration in Days").setStyle(TextInputStyle.Short).setRequired(true)),
                            new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('amount').setLabel("Amount of Keys (Max 1000)").setStyle(TextInputStyle.Short).setRequired(true))
                        );
                        return await interaction.showModal(modal);
                    } catch (e) { console.error(e); }
                }

                if (action === 'userinfo') {
                    try {
                        const modal = new ModalBuilder().setCustomId(`modal_userinfo_${projectId}`).setTitle('Lookup User');
                        modal.addComponents(new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('userId').setLabel("Discord User ID").setStyle(TextInputStyle.Short).setRequired(true)));
                        return await interaction.showModal(modal);
                    } catch (e) { console.error(e); }
                }

                if (action === 'clearkeys') {
                    const initialLength = project.hwidKeys ? project.hwidKeys.length : 0;
                    if (project.hwidKeys) {
                        project.hwidKeys = project.hwidKeys.filter(k => {
                            const isUnused = !k.userId;
                            const isExpired = Date.now() > k.expiresAt;
                            return !isUnused && !isExpired; 
                        });
                    }
                    writeDB(db);
                    const removed = initialLength - (project.hwidKeys ? project.hwidKeys.length : 0);
                    
                    const okEmbed = new EmbedBuilder().setColor(0xF59E0B).setDescription(`${EMOJI_BROOM} **Cleared ${removed} unused or expired keys** from ${project.name}.`);
                    return interaction.update({ content: "", embeds: [okEmbed], components: [] });
                }
            }
        }

        if (interaction.isButton()) {
            const parts = interaction.customId.split('_');
            const prefix = parts;

            if (prefix === 'authgw') {
                try {
                    await interaction.deferReply({ ephemeral: true });
                    const gwId = parts.slice(2).join('_');
                    const db = readDB();
                    const gw = db.giveaways.find(g => g.id === gwId);
                    
                    if (!gw) return interaction.editReply({ content: "Giveaway not found or expired." });
                    if (gw.ended) return interaction.editReply({ content: "Giveaway has ended." });

                    const project = db.projects.find(p => p.id === gw.projectId);
                    if (!project) return interaction.editReply({ content: "Project not found." });

                    if (project.discordConfig && project.discordConfig.roleId) {
                        try {
                            const member = await interaction.guild.members.fetch(interaction.user.id);
                            if (member && member.roles.cache.has(project.discordConfig.roleId)) {
                                return interaction.editReply({ content: "You already have the customer role for this project, so you cannot enter!" });
                            }
                        } catch(e) {}
                    }

                    if (gw.participants.includes(interaction.user.id)) {
                        return interaction.editReply({ content: "You have already entered this giveaway!" });
                    }

                    gw.participants.push(interaction.user.id);
                    writeDB(db);
                    return interaction.editReply({ content: `${EMOJI_TADA} You have successfully entered the giveaway!` });
                } catch(e) {
                    return interaction.editReply({ content: "An error occurred while joining." });
                }
            }

            if (prefix === 'auth') {
                const action = parts;
                const projectId = parts.slice(2).join('_');
                
                const db = readDB();
                const project = db.projects.find(p => p.id === projectId);
                if (!project) return interaction.reply({ content: "Project no longer exists.", ephemeral: true });

                if (action === 'redeem') {
                    const modal = new ModalBuilder().setCustomId(`modal_redeem_${projectId}`).setTitle('Redeem License Key');
                    const keyInput = new TextInputBuilder().setCustomId('keyInput').setLabel("Enter your HWID Key").setStyle(TextInputStyle.Short).setRequired(true);
                    modal.addComponents(new ActionRowBuilder().addComponents(keyInput));
                    return await interaction.showModal(modal).catch(console.error);
                }

                await interaction.deferReply({ ephemeral: true });

                const userKey = (project.hwidKeys || []).find(k => k.userId === interaction.user.id);
                if (!userKey) return interaction.editReply({ content: "You do not have a claimed key for this project." });

                const loaderCode = `getgenv().script_key = "${userKey.key}"\nloadstring(game:HttpGet("${HOST_URL}/loader/${projectId}"))()`;

                if (action === 'getscriptembed') {
                    const scriptEmbed = new EmbedBuilder()
                        .setTitle('Your Script Loader')
                        .setDescription(`\`\`\`lua\n${loaderCode}\n\`\`\``)
                        .setColor(0x4F6CEE)
                        .setFooter({ text: "Do not share your key with anyone." });
                    return interaction.editReply({ embeds: [scriptEmbed] });
                }

                if (action === 'getscriptnoembed') {
                    return interaction.editReply({ content: loaderCode });
                }

                if (action === 'reset') {
                    const cooldownMs = (project.hwidResetCooldown || 24) * 60 * 60 * 1000;
                    if (Date.now() - (userKey.lastReset || 0) < cooldownMs) {
                        const hoursLeft = Math.ceil((cooldownMs - (Date.now() - userKey.lastReset)) / 3600000);
                        return interaction.editReply({ content: `Cooldown active. You can reset your HWID again in ${hoursLeft} hours.` });
                    }
                    userKey.hwid = null;
                    userKey.ip = null;
                    userKey.lastReset = Date.now();
                    writeDB(db);
                    return interaction.editReply({ content: `${EMOJI_CHECK} Your HWID has been successfully reset. Run the script again to bind your new device.` });
                }

                if (action === 'stats') {
                    const daysLeft = Math.max(0, Math.ceil((userKey.expiresAt - Date.now()) / (1000 * 60 * 60 * 24)));
                    const statusStr = userKey.hwid ? "Locked to Device" : "Unbound";
                    const statsEmbed = new EmbedBuilder()
                        .setTitle("Account Statistics")
                        .setColor(0x4F6CEE)
                        .addFields(
                            { name: "Project", value: project.name, inline: true },
                            { name: "Days Remaining", value: `${daysLeft} Days`, inline: true },
                            { name: "HWID Status", value: statusStr, inline: false }
                        );
                    return interaction.editReply({ embeds: [statsEmbed] });
                }
            }
        }

        if (interaction.isModalSubmit()) {
            const parts = interaction.customId.split('_');
            const prefix = parts.shift();
            const action = parts.shift();
            
            if (prefix !== 'modal') return;

            const db = readDB();

            if (action === 'setadminrole') {
                await interaction.deferReply({ ephemeral: true });
                const roleId = interaction.fields.getTextInputValue('roleId').trim();
                if (!db.guildConfigs) db.guildConfigs = {};
                if (!db.guildConfigs[interaction.guildId]) db.guildConfigs[interaction.guildId] = {};
                db.guildConfigs[interaction.guildId].adminRoleId = roleId;
                writeDB(db);
                const okEmbed = new EmbedBuilder().setColor(0x10B981).setDescription(`${EMOJI_CHECK} Admin Role successfully set to <@&${roleId}>.`);
                return interaction.editReply({ embeds: [okEmbed] });
            }

            if (action === 'resethwid') {
                await interaction.deferReply({ ephemeral: true });
                const keyStr = interaction.fields.getTextInputValue('hwidKey').trim();
                let found = false;
                db.projects.forEach(p => {
                    const k = (p.hwidKeys || []).find(x => x.key === keyStr);
                    if (k) { k.hwid = null; k.ip = null; k.lastReset = Date.now(); found = true; }
                });
                if (found) { 
                    writeDB(db); 
                    const okEmbed = new EmbedBuilder().setColor(0x10B981).setDescription(`${EMOJI_CHECK} HWID successfully reset for that key.`);
                    return interaction.editReply({ embeds: [okEmbed] });
                }
                return interaction.editReply({ content: "Key not found." });
            }

            if (action === 'extendkey') {
                await interaction.deferReply({ ephemeral: true });
                const keyStr = interaction.fields.getTextInputValue('hwidKey').trim();
                const days = parseInt(interaction.fields.getTextInputValue('days').trim());
                if (isNaN(days)) return interaction.editReply({ content: "Invalid number of days." });

                let found = false;
                db.projects.forEach(p => {
                    const k = (p.hwidKeys || []).find(x => x.key === keyStr);
                    if (k) { k.expiresAt += (days * 24 * 60 * 60 * 1000); k.roleRemoved = false; found = true; }
                });
                if (found) { 
                    writeDB(db); 
                    const okEmbed = new EmbedBuilder().setColor(0x10B981).setDescription(`${EMOJI_CHECK} Key successfully extended by **${days}** days.`);
                    return interaction.editReply({ embeds: [okEmbed] }); 
                }
                return interaction.editReply({ content: "Key not found." });
            }

            if (action === 'revokekey') {
                await interaction.deferReply({ ephemeral: true });
                const keyStr = interaction.fields.getTextInputValue('hwidKey').trim();
                let found = false;
                db.projects.forEach(async p => {
                    const idx = (p.hwidKeys || []).findIndex(x => x.key === keyStr);
                    if (idx !== -1) { 
                        const k = p.hwidKeys[idx];
                        if (k.userId && p.discordConfig && p.discordConfig.roleId) {
                            try {
                                const guild = await client.guilds.fetch(p.discordConfig.guildId);
                                const member = await guild.members.fetch(k.userId);
                                await member.roles.remove(p.discordConfig.roleId);
                            } catch (e) {}
                        }
                        p.hwidKeys.splice(idx, 1); 
                        found = true; 
                    }
                });
                if (found) { 
                    writeDB(db); 
                    const okEmbed = new EmbedBuilder().setColor(0xEF4444).setDescription(`${EMOJI_TRASH} Key successfully revoked and deleted.`);
                    return interaction.editReply({ embeds: [okEmbed] }); 
                }
                return interaction.editReply({ content: "Key not found." });
            }

            if (action === 'userinfo') {
                await interaction.deferReply({ ephemeral: true });
                const projectId = parts.join('_');
                const project = db.projects.find(p => p.id === projectId);
                if (!project) return interaction.editReply({ content: "Project no longer exists." });

                const targetUserId = interaction.fields.getTextInputValue('userId').trim();
                const userKey = (project.hwidKeys || []).find(k => k.userId === targetUserId);
                if (!userKey) {
                    const errEmbed = new EmbedBuilder().setColor(0xEF4444).setDescription(`${EMOJI_CROSS} <@${targetUserId}> does not have a key for this project.`);
                    return interaction.editReply({ embeds: [errEmbed] });
                }

                const daysLeft = Math.max(0, Math.ceil((userKey.expiresAt - Date.now()) / (1000 * 60 * 60 * 24)));
                const statusStr = userKey.hwid ? `Locked to Device (${userKey.hwid.substring(0, 8)}...)` : "Unbound";

                let targetUsername = "User";
                try {
                    const tUser = await client.users.fetch(targetUserId);
                    targetUsername = tUser.username;
                } catch(e) {}

                const infoEmbed = new EmbedBuilder()
                    .setTitle(`User Info: ${targetUsername}`)
                    .setColor(0x4F6CEE)
                    .addFields(
                        { name: "Project", value: project.name, inline: true },
                        { name: "Key", value: `||${userKey.key}||`, inline: true },
                        { name: "Days Left", value: `${daysLeft} Days`, inline: true },
                        { name: "HWID Status", value: statusStr, inline: true }
                    );
                return interaction.editReply({ embeds: [infoEmbed] });
            }

            if (action === 'setuppanel') {
                await interaction.deferReply({ ephemeral: true });
                const projectId = parts.join('_');
                const project = db.projects.find(p => p.id === projectId);
                if (!project) return interaction.editReply({ content: "Project no longer exists." });

                const roleId = interaction.fields.getTextInputValue('roleId').trim();
                project.discordConfig = { guildId: interaction.guildId, roleId: roleId, channelId: interaction.channelId };
                writeDB(db);
                
                const embed = new EmbedBuilder()
                    .setTitle(`${project.name} - Script Panel`)
                    .setColor(0x4F6CEE)
                    .setDescription("**Script:** Custom Loader\n\nUse the buttons below to manage your account:\n• Redeem your key to link your Discord account\n• Get the script download code\n• Reset your hardware ID\n• View your account statistics");

                const row1 = new ActionRowBuilder().addComponents(
                    new ButtonBuilder().setCustomId(`auth_redeem_${project.id}`).setLabel('Redeem Key').setEmoji("🔑").setStyle(ButtonStyle.Success),
                    new ButtonBuilder().setCustomId(`auth_stats_${project.id}`).setLabel('Status').setEmoji("📊").setStyle(ButtonStyle.Secondary)
                );
                const row2 = new ActionRowBuilder().addComponents(
                    new ButtonBuilder().setCustomId(`auth_getscriptembed_${project.id}`).setLabel('Copy Script').setEmoji("📥").setStyle(ButtonStyle.Primary),
                    new ButtonBuilder().setCustomId(`auth_getscriptnoembed_${project.id}`).setLabel('Copy Script (No Embed)').setEmoji("📋").setStyle(ButtonStyle.Primary)
                );
                const row3 = new ActionRowBuilder().addComponents(
                    new ButtonBuilder().setCustomId(`auth_reset_${project.id}`).setLabel('Reset HWID').setEmoji("🔄").setStyle(ButtonStyle.Danger)
                );

                const channel = await client.channels.fetch(interaction.channelId).catch(() => null);
                if (!channel) return interaction.editReply({ content: "❌ Could not access the channel." });

                await channel.send({ embeds: [embed], components: [row1, row2, row3] }).catch(() => {});
                
                const okEmbed = new EmbedBuilder().setColor(0x10B981).setDescription(`${EMOJI_CHECK} Panel deployed successfully.`);
                return interaction.editReply({ embeds: [okEmbed] });
            }

            if (action === 'genkey') {
                await interaction.deferReply({ ephemeral: true });
                const projectId = parts.join('_');
                const project = db.projects.find(p => p.id === projectId);
                if (!project) return interaction.editReply({ content: "Project no longer exists." });

                const days = parseInt(interaction.fields.getTextInputValue('days'));
                const amount = parseInt(interaction.fields.getTextInputValue('amount'));
                if (isNaN(days) || isNaN(amount)) return interaction.editReply({ content: "Invalid numbers provided." });

                const expiresAt = Date.now() + (days * 24 * 60 * 60 * 1000);
                if (!project.hwidKeys) project.hwidKeys = [];
                
                const generated = [];
                for(let i=0; i<amount; i++) {
                    const newKey = crypto.randomBytes(12).toString('hex').toLowerCase();
                    generated.push(newKey);
                    project.hwidKeys.push({ key: newKey, createdAt: Date.now(), expiresAt: expiresAt, userId: null, hwid: null, ip: null, roleRemoved: false });
                }
                writeDB(db);

                const okEmbed = new EmbedBuilder()
                    .setTitle(`✅ Generated ${amount} Key(s)`)
                    .setColor(0x10B981)
                    .addFields(
                        { name: 'Project', value: project.name, inline: true },
                        { name: 'Duration', value: `${days} Days`, inline: true }
                    );

                if (amount > 15) {
                    const buffer = Buffer.from(generated.join('\n'), 'utf-8');
                    const attachment = new AttachmentBuilder(buffer, { name: 'keys.txt' });
                    okEmbed.setDescription("Keys have been attached in the text file below.");
                    return interaction.editReply({ embeds: [okEmbed], files: [attachment] });
                } else {
                    const keyList = generated.map(k => `\`${k}\``).join('\n');
                    okEmbed.setDescription(`**Keys:**\n${keyList}`);
                    return interaction.editReply({ embeds: [okEmbed] });
                }
            }

            if (action === 'giveaway') {
                await interaction.deferReply({ ephemeral: true });
                const projectId = parts.join('_');
                const project = db.projects.find(p => p.id === projectId);
                if (!project) return interaction.editReply({ content: "Project no longer exists." });

                const winners = parseInt(interaction.fields.getTextInputValue('winners'));
                const keyDays = parseInt(interaction.fields.getTextInputValue('keyDays'));
                const durationMins = parseInt(interaction.fields.getTextInputValue('durationMins'));

                if (isNaN(winners) || isNaN(keyDays) || isNaN(durationMins)) {
                    return interaction.editReply({ content: "Invalid numbers provided." });
                }

                const gwId = crypto.randomBytes(8).toString('hex');
                const endsAt = Date.now() + (durationMins * 60 * 1000);
                const timestamp = Math.floor(endsAt / 1000);

                const embed = new EmbedBuilder()
                    .setTitle(`🎉 **${project.name} Script Giveaway!** 🎉`)
                    .setColor(0x4F6CEE)
                    .setDescription(`**Prize:** ${winners}x Key(s) (${keyDays} Days)\n**Ends:** <t:${timestamp}:R> (<t:${timestamp}:f>)\n\nClick the button below to enter!`)
                    .setFooter({ text: "Luau-Auth Giveaways" });

                const rowBtn = new ActionRowBuilder().addComponents(
                    new ButtonBuilder().setCustomId(`authgw_join_${gwId}`).setLabel('Join Giveaway').setEmoji("🎉").setStyle(ButtonStyle.Success)
                );

                const channel = await client.channels.fetch(interaction.channelId).catch(() => null);
                if (!channel) return interaction.editReply({ content: `❌ Could not access the channel.` });

                const msg = await channel.send({ embeds: [embed], components: [rowBtn] });

                db.giveaways.push({
                    id: gwId,
                    messageId: msg.id,
                    channelId: msg.channelId,
                    guildId: msg.guildId,
                    projectId: project.id,
                    winnersCount: winners,
                    keyDays: keyDays,
                    endsAt: endsAt,
                    ended: false,
                    participants: []
                });
                writeDB(db);

                return interaction.editReply({ content: `✅ Giveaway deployed successfully!` });
            }

        }
    } catch (globalError) {
        console.error("Global Interaction Error:", globalError);
        try {
            if (interaction.isRepliable() && !interaction.replied && !interaction.deferred) {
                await interaction.reply({ content: "An error occurred while processing this command.", ephemeral: true });
            } else if (interaction.deferred && !interaction.replied) {
                await interaction.editReply({ content: "An error occurred while processing this command." });
            }
        } catch (e) {}
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`[OK] Web Server is running on port ${PORT}`);
});

if (DISCORD_BOT_TOKEN) {
    console.log("Attempting to log in to Discord...");
    client.login(DISCORD_BOT_TOKEN).then(() => {
        console.log(`[OK] Discord Bot Successfully Logged In as ${client.user.tag}`);
    }).catch((err) => {
        console.error("[ERROR] DISCORD BOT CRASHED ON STARTUP:", err.message);
    });
}console.log("Starting Sanctuary Backend...");

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Client, GatewayIntentBits, ActionRowBuilder, ButtonBuilder, ButtonStyle, ModalBuilder, TextInputBuilder, TextInputStyle, EmbedBuilder, REST, Routes, SlashCommandBuilder, AttachmentBuilder, PermissionFlagsBits, StringSelectMenuBuilder } = require('discord.js');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(__dirname));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

const dbPath = path.join(__dirname, 'database.json');
const ADMIN_IDS = ["1284247278957367337", "1282859051092414586"];

// Secure Environment Variables (Set these in Railway)
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const HOST_URL = process.env.HOST_URL;
const REDIRECT_URI = `${HOST_URL}/api/auth/callback`;

// Safe Unicode Emojis
const EMOJI_CHECK = "\u2705";
const EMOJI_CROSS = "\u274C";
const EMOJI_TADA = "\uD83C\uDF89";
const EMOJI_SAD = "\uD83D\uDE22";
const EMOJI_BROOM = "\uD83E\uDDF9";
const EMOJI_TRASH = "\uD83D\uDDD1\uFE0F";

const client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent] });

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
    const keyData = db.apiKeys[apiKey];
    if (!keyData) return res.status(401).json({ error: "Invalid API Key" });
    if (Date.now() > keyData.expiresAt) return res.status(403).json({ error: "API Key expired" });
    next();
};

app.get('/api/auth/discord', (req, res) => {
    if (!DISCORD_CLIENT_ID || !HOST_URL) return res.status(500).send("Railway Variables not configured.");
    res.redirect(`https://discord.com/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=identify`);
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
        
        const safeUserObj = {
            id: userData.id,
            username: userData.username,
            avatar: userData.avatar || '',
            isAdmin: ADMIN_IDS.includes(userData.id)
        };
        
        const htmlResponse = `
            <script>
                localStorage.setItem('sanctuary_user', JSON.stringify(${JSON.stringify(safeUserObj)}));
                window.location.href = "/";
            </script>
        `;
        res.send(htmlResponse);
    } catch (err) {
        res.status(500).send("Authentication failed.");
    }
});

app.post('/api/link-key', (req, res) => {
    const { apiKey, discordId, discordName } = req.body;
    const db = readDB();
    if (!db.apiKeys[apiKey]) return res.status(400).json({ error: "Invalid Key" });
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

const requireAdmin = (req, res, next) => {
    if (!ADMIN_IDS.includes(req.body.discordId)) return res.status(403).json({ error: "Unauthorized" });
    next();
};

app.post('/api/admin/keys', requireAdmin, (req, res) => res.json({ keys: readDB().apiKeys }));

app.post('/api/admin/generate-key', requireAdmin, (req, res) => {
    const db = readDB();
    const newKey = crypto.randomBytes(12).toString('hex').toLowerCase();
    const expiresAt = Date.now() + (parseInt(req.body.days) * 24 * 60 * 60 * 1000);
    db.apiKeys[newKey] = { createdAt: Date.now(), expiresAt: expiresAt, userId: null, username: null };
    writeDB(db);
    res.json({ key: newKey, expiresAt: expiresAt });
});

app.post('/api/admin/extend-key', requireAdmin, (req, res) => {
    const { targetKey, days } = req.body;
    const db = readDB();
    if (!db.apiKeys[targetKey]) return res.status(404).json({ error: "Not found" });
    db.apiKeys[targetKey].expiresAt += (parseInt(days) * 24 * 60 * 60 * 1000);
    writeDB(db);
    res.json({ success: true });
});

app.post('/api/admin/revoke-key', requireAdmin, (req, res) => {
    const db = readDB();
    if (db.apiKeys[req.body.targetKey]) {
        delete db.apiKeys[req.body.targetKey];
        writeDB(db);
    }
    res.json({ success: true });
});

app.get('/api/sync', (req, res) => {
    const { discordId } = req.query;
    const db = readDB();
    if (!discordId) return res.json({ projects: [] });
    const isAdmin = ADMIN_IDS.includes(discordId);
    let needsSave = false;
    db.projects.forEach(p => {
        if (!p.ownerId) { p.ownerId = discordId; needsSave = true; }
        if (p.freeMode === undefined) { p.freeMode = true; needsSave = true; }
        if (p.hwidResetCooldown === undefined) { p.hwidResetCooldown = 24; needsSave = true; }
        if (!p.hwidKeys) { p.hwidKeys = []; needsSave = true; }
    });
    if (needsSave) writeDB(db);
    res.json({ projects: isAdmin ? db.projects : db.projects.filter(p => p.ownerId === discordId) });
});

app.post('/api/sync', requireValidAccess, (req, res) => {
    const db = readDB();
    const incomingProjects = req.body.projects;
    const discordId = req.body.discordId;
    const isAdmin = ADMIN_IDS.includes(discordId);
    if (isAdmin) {
        db.projects = incomingProjects;
    } else {
        const otherUsersProjects = db.projects.filter(p => p.ownerId !== discordId);
        const userProjectsToSave = incomingProjects.filter(p => p.ownerId === discordId || !p.ownerId);
        userProjectsToSave.forEach(p => p.ownerId = discordId);
        db.projects = [...otherUsersProjects, ...userProjectsToSave];
    }
    writeDB(db);
    res.json({ success: true });
});

app.get('/raw/:projectId/:scriptId', async (req, res) => {
    const { projectId, scriptId } = req.params;
    const { key, hwid } = req.query;
    const acceptHeader = req.headers['accept'] || "";
    
    if (acceptHeader.includes("text/html")) {
        res.type('text/plain');
        return res.send(`print("Script ID: ${scriptId}")`);
    }
    
    const db = readDB();
    const project = db.projects.find(p => p.id === projectId);
    
    let currentIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || "UNKNOWN";
    if (typeof currentIp === 'string' && currentIp.includes(',')) {
        currentIp = currentIp.split(',').shift().trim();
    }

    if (project) {
        const script = project.scripts.find(s => s.id === scriptId);
        if (script) {
            res.type('text/plain');
            if (script.status !== 'Active') {
                return res.send(`print("This script is no longer working.")`);
            }
            
            let finalLuaCode = `
local v0 = (getexecutorname and getexecutorname()) or ""
local v1 = ${script.allowSolaraXeno === true ? "true" : "false"}
local v2 = function()
    print("Running Sanctuary Engine...")
    pcall(function()
        if not v1 then
            if v0 and (v0:lower():find("xeno") or v0:lower():find("solara")) then
                game:GetService("Players").LocalPlayer:Kick("You are using an executor that doesn't support this script.\\nExecutor: [" .. v0 .. "]\\nPlease use another executor.")
            else
                if v0 ~= nil and v0 ~= "" then
                    print("Executor:" .. v0)
                    print("Valid Executor.")
                end
            end
        end
    end)
end
v2()

`;

            if (project.freeMode === false) {
                if (!key) return res.send(`game:GetService("Players").LocalPlayer:Kick("Sanctuary: No Script Key Provided")`);
                const hwidKey = (project.hwidKeys || []).find(k => k.key === key);
                if (!hwidKey || hwidKey.expiresAt < Date.now()) {
                    return res.send(`game:GetService("Players").LocalPlayer:Kick("Sanctuary: Invalid or expired key")`);
                }
                if (!hwidKey.hwid) {
                    hwidKey.hwid = hwid || "UNKNOWN";
                    hwidKey.ip = currentIp;
                    writeDB(db);
                } else {
                    if (hwidKey.hwid !== hwid && hwid) {
                        return res.send(`game:GetService("Players").LocalPlayer:Kick("Sanctuary: Invalid HWID. Key is locked to another device.")`);
                    }
                    if (hwidKey.ip && hwidKey.ip !== currentIp && currentIp !== "UNKNOWN") {
                        return res.send(`game:GetService("Players").LocalPlayer:Kick("Sanctuary: Invalid IP Address. Key is locked to another network.")`);
                    }
                }
                if (project.discordConfig && project.discordConfig.roleId && hwidKey.userId) {
                    try {
                        const guild = await client.guilds.fetch(project.discordConfig.guildId);
                        const member = await guild.members.fetch(hwidKey.userId);
                        if (!member.roles.cache.has(project.discordConfig.roleId)) {
                            return res.send(`game:GetService("Players").LocalPlayer:Kick("Sanctuary: Missing Discord Role")`);
                        }
                    } catch (err) {
                        return res.send(`game:GetService("Players").LocalPlayer:Kick("Sanctuary: Discord Authentication Error")`);
                    }
                }

                finalLuaCode += `
local _authKey = getgenv().script_key
local _authHwid1 = (gethwid and gethwid()) or "nohwid"
local _authHwid2 = game:GetService("RbxAnalyticsService"):GetClientId()
local _authHwid = _authHwid1 .. "_" .. _authHwid2
if not _authKey or _authKey == "" then
    game:GetService("Players").LocalPlayer:Kick("Sanctuary: Whitelist Error - No Key Provided")
    return
end
if _authKey ~= "${key}" then
    game:GetService("Players").LocalPlayer:Kick("Sanctuary: Whitelist Error - Key Mismatch")
    return
end\n\n`;
            }
            
            script.executions = (script.executions || 0) + 1;
            if (!script.executionHistory) script.executionHistory = {};
            const today = new Date().toISOString().split('T').shift();
            script.executionHistory[today] = (script.executionHistory[today] || 0) + 1;
            writeDB(db);
            
            if (project.webhookUrl && project.webhookUrl.trim() !== "") {
                finalLuaCode += `
pcall(function()
    local request = http_request or syn and syn.request or request
    if not request then return end
    local HttpService = game:GetService("HttpService")
    local Players = game:GetService("Players")
    local UIS = game:GetService("UserInputService")
    local player = Players.LocalPlayer
    local executor = (getexecutorname and getexecutorname()) or (identifyexecutor and identifyexecutor()) or "Unknown"
    local deviceType = "Unknown"
    if UIS.TouchEnabled and not UIS.KeyboardEnabled then deviceType = "Mobile"
    elseif UIS.GamepadEnabled and not UIS.KeyboardEnabled then deviceType = "Console"
    elseif UIS.KeyboardEnabled then deviceType = "PC" end
    getgenv().execCount = (getgenv().execCount or 0) + 1
    local payload = {
        username = "Sanctuary Logger",
        embeds = {{
            title = "Execution Log",
            color = 0x4F6CEE,
            fields = {
                { name = "User Info", value = "Name: " .. player.Name .. "\\nUserId: " .. player.UserId, inline = false },
                { name = "Script Triggered", value = "${script.name}", inline = false },
                { name = "Executor", value = executor, inline = false },
                { name = "Device", value = deviceType, inline = true },
                { name = "IP Address", value = "${currentIp}", inline = true },
                { name = "Executions", value = tostring(getgenv().execCount), inline = true }
            }
        }}
    }
    request({ Url = "${project.webhookUrl}", Method = "POST", Headers = { ["Content-Type"] = "application/json" }, Body = HttpService:JSONEncode(payload) })
end)\n\n`;
            }
            return res.send(finalLuaCode + (script.code || `print("Empty script")`));
        }
    }
    res.status(404).send(`print("Error: Script or Project not found")`);
});

app.get('/loader/:projectId', (req, res) => {
    const project = readDB().projects.find(p => p.id === req.params.projectId);
    if (project) {
        res.type('text/plain');
        let scriptsTable = "";
        (project.scripts || []).forEach(s => {
            if (s.gameId && s.gameId !== "") {
                scriptsTable += `    ["${s.gameId}"] = "${HOST_URL}/raw/${project.id}/${s.id}",\n`;
            } else {
                scriptsTable += `    ["Universal"] = "${HOST_URL}/raw/${project.id}/${s.id}",\n`;
            }
        });
        
        let authSnippet = "";
        let callSnippet = `loadstring(game:HttpGet(Script))()`;

        if (project.freeMode === false) {
            authSnippet = `\nlocal AuthKey = getgenv().script_key or ""\nlocal hw1 = (gethwid and gethwid()) or "nohwid"\nlocal hw2 = game:GetService("RbxAnalyticsService"):GetClientId()\nlocal hwid = hw1 .. "_" .. hw2\n`;
            callSnippet = `loadstring(game:HttpGet(Script .. "?key=" .. AuthKey .. "&hwid=" .. hwid))()`;
        }
        
        let dynamicLoader = `local ProjectId = "${project.id}"\n`;
        dynamicLoader += `local Scripts = {\n${scriptsTable}}\n`;
        dynamicLoader += `local Script = Scripts[tostring(game.GameId)] or Scripts[game.GameId] or Scripts["Universal"]\n`;
        dynamicLoader += `if Script then${authSnippet}\n    ${callSnippet}\nelse\n    warn("Sanctuary: No valid script found for this game.")\nend`;
        
        return res.send(dynamicLoader);
    }
    res.status(404).send(`print("Error: Project not found")`);
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
    if (!DISCORD_BOT_TOKEN) {
        console.log("❌ DISCORD_BOT_TOKEN is missing in Railway Variables!");
        return;
    }
    const rest = new REST({ version: '10' }).setToken(DISCORD_BOT_TOKEN);
    try {
        const cmdJson = cmds.map(c => c.toJSON());
        await rest.put(Routes.applicationCommands(client.user.id), { body: cmdJson });
        console.log("✅ Slash commands fully registered.");
    } catch (error) {
        console.log("❌ Failed to register commands:", error);
    }
});

client.on('messageCreate', async message => {
    if (message.author.bot || !message.guild) return;
    if (message.member && message.member.permissions.has(PermissionFlagsBits.Administrator)) return;
    if (ADMIN_IDS.includes(message.author.id)) return;

    const content = message.content.toLowerCase();
    const inviteRegex = /(discord\.(gg|com\/invite)\/|dsc\.gg\/|invite\.gg\/)/i;
    const promoRegex = /(youtube\.com\/(c|channel)\/|twitch\.tv\/|onlyfans\.com\/|tiktok\.com\/@|twitter\.com\/)/i;
    
    if (inviteRegex.test(content) || promoRegex.test(content)) {
        await message.delete().catch(() => {});
        const warnMsg = await message.channel.send(`<@${message.author.id}>, posting invites or self-promotion is not allowed!`);
        setTimeout(() => warnMsg.delete().catch(() => {}), 5000);
        return;
    }

    if (message.mentions.users.size > 4) {
        await message.delete().catch(() => {});
        const warnMsg = await message.channel.send(`<@${message.author.id}>, please do not mass-mention users.`);
        setTimeout(() => warnMsg.delete().catch(() => {}), 5000);
        return;
    }
});

setInterval(async () => {
    const db = readDB();
    let needsSave = false;
    
    for (let p of db.projects) {
        if (!p.hwidKeys) continue;
        for (let k of p.hwidKeys) {
            if (k.userId && Date.now() > k.expiresAt && !k.roleRemoved) {
                if (p.discordConfig && p.discordConfig.roleId) {
                    try {
                        const guild = await client.guilds.fetch(p.discordConfig.guildId);
                        const member = await guild.members.fetch(k.userId);
                        await member.roles.remove(p.discordConfig.roleId);
                    } catch (err) {}
                }
                k.roleRemoved = true;
                needsSave = true;
            }
        }
    }

    for (let gw of db.giveaways) {
        if (!gw.ended && Date.now() >= gw.endsAt) {
            gw.ended = true;
            needsSave = true;

            const project = db.projects.find(p => p.id === gw.projectId);
            if (!project) continue;

            try {
                const channel = await client.channels.fetch(gw.channelId).catch(() => null);
                if (!channel) continue;

                if (!gw.participants || gw.participants.length === 0) {
                    const failEmbed = new EmbedBuilder()
                        .setTitle(`${EMOJI_TADA} **Giveaway Ended** ${EMOJI_TADA}`)
                        .setColor(0x3f3f46)
                        .setDescription(`Nobody entered the giveaway for **${project.name}**. ${EMOJI_SAD}`);
                    await channel.send({ embeds: [failEmbed] }).catch(() => {});
                } else {
                    const shuffled = gw.participants.sort(() => 0.5 - Math.random());
                    const winners = shuffled.slice(0, gw.winnersCount);

                    const winnerMentions = [];
                    const expiresAt = Date.now() + (gw.keyDays * 24 * 60 * 60 * 1000);
                    
                    for (let wId of winners) {
                        winnerMentions.push(`<@${wId}>`);
                        const newKey = crypto.randomBytes(12).toString('hex').toLowerCase();
                        
                        if (!project.hwidKeys) project.hwidKeys = [];
                        project.hwidKeys.push({
                            key: newKey,
                            note: "Giveaway Winner",
                            createdAt: Date.now(),
                            expiresAt: expiresAt,
                            userId: wId,
                            hwid: null,
                            ip: null,
                            roleRemoved: false
                        });

                        if (project.discordConfig && project.discordConfig.roleId) {
                            try {
                                const guild = await client.guilds.fetch(gw.guildId);
                                const member = await guild.members.fetch(wId);
                                await member.roles.add(project.discordConfig.roleId);
                            } catch(e) {}
                        }

                        try {
                            const user = await client.users.fetch(wId);
                            const loaderCode = `getgenv().script_key = "${newKey}"\nloadstring(game:HttpGet("${HOST_URL}/loader/${project.id}"))()`;
                            const dmEmbed = new EmbedBuilder()
                                .setTitle(`${EMOJI_TADA} You won the Giveaway!`)
                                .setColor(0x4F6CEE)
                                .setDescription(`Congratulations! You won a **${gw.keyDays} Day** key for **${project.name}**!\n\nYour key has automatically been redeemed to your Discord account, and you have been given the customer role.\n\n**Your Script Loader:**\n\`\`\`lua\n${loaderCode}\n\`\`\``);
                            await user.send({ embeds: [dmEmbed] }).catch(() => {});
                        } catch(e) {}
                    }

                    const winEmbed = new EmbedBuilder()
                        .setTitle(`${EMOJI_TADA} **Giveaway Winners!** ${EMOJI_TADA}`)
                        .setColor(0x10b981)
                        .setDescription(`**Prize:** ${gw.winnersCount}x Key(s) for ${project.name}\n**Winners:** ${winnerMentions.join(', ')}\n\n*Winners have been given the customer role and DMed their scripts automatically!*`);
                    
                    await channel.send({ embeds: [winEmbed] }).catch(() => {});
                }

                try {
                    const msg = await channel.messages.fetch(gw.messageId);
                    const endedRow = new ActionRowBuilder().addComponents(
                        new ButtonBuilder().setCustomId('ended_btn').setLabel('Giveaway Ended').setStyle(ButtonStyle.Secondary).setDisabled(true)
                    );
                    await msg.edit({ components: [endedRow] });
                } catch(e) {}

            } catch (e) {}
        }
    }

    if (needsSave) writeDB(db);
}, 15 * 1000);

const buildProjectSelect = (customId, interaction, db) => {
    const isGlobalAdmin = ADMIN_IDS.includes(interaction.user.id);
    const userProjects = isGlobalAdmin ? db.projects : db.projects.filter(p => p.ownerId === interaction.user.id);
    
    if (userProjects.length === 0) return null;

    const options = userProjects.map(p => ({
        label: p.name,
        description: `Project ID: ${p.id.substring(0, 20)}...`,
        value: p.id
    })).slice(0, 25);

    const selectMenu = new StringSelectMenuBuilder()
        .setCustomId(customId)
        .setPlaceholder('Select a project')
        .addOptions(options);

    return new ActionRowBuilder().addComponents(selectMenu);
};

client.on('interactionCreate', async interaction => {
    try {
        if (interaction.isCommand()) {
            if (!interaction.guild) return interaction.reply({ content: "Commands must be used in a server.", ephemeral: true });

            const db = readDB();

            if (interaction.commandName === 'login') {
                const apiKey = interaction.options.getString('api_key');
                if (!db.apiKeys[apiKey]) {
                    const errEmbed = new EmbedBuilder().setColor(0xEF4444).setDescription(`${EMOJI_CROSS} Invalid API Key.`);
                    return interaction.reply({ embeds: [errEmbed], ephemeral: true });
                }
                if (Date.now() > db.apiKeys[apiKey].expiresAt) {
                    const errEmbed = new EmbedBuilder().setColor(0xEF4444).setDescription(`${EMOJI_CROSS} API Key is expired.`);
                    return interaction.reply({ embeds: [errEmbed], ephemeral: true });
                }

                db.apiKeys[apiKey].userId = interaction.user.id;
                db.apiKeys[apiKey].username = interaction.user.username;
                writeDB(db);

                const okEmbed = new EmbedBuilder()
                    .setColor(0x10B981)
                    .setTitle(`${EMOJI_CHECK} Successfully Logged In`)
                    .setDescription("Your Discord account is now securely linked to this API Key. You can now use bot commands.");
                return interaction.reply({ embeds: [okEmbed], ephemeral: true });
            }

            const isGlobalAdmin = ADMIN_IDS.includes(interaction.user.id);
            const isServerOwner = interaction.user.id === interaction.guild.ownerId;
            
            let hasLinkedApiKey = false;
            for (let k in db.apiKeys) {
                if (db.apiKeys[k].userId === interaction.user.id && Date.now() < db.apiKeys[k].expiresAt) {
                    hasLinkedApiKey = true;
                    break;
                }
            }

            let hasAdminRole = false;
            if (interaction.guildId && db.guildConfigs && db.guildConfigs[interaction.guildId]) {
                const adminRoleId = db.guildConfigs[interaction.guildId].adminRoleId;
                if (adminRoleId) {
                    try {
                        const member = await interaction.guild.members.fetch(interaction.user.id);
                        if (member.roles.cache.has(adminRoleId)) hasAdminRole = true;
                    } catch(e){}
                }
            }
            
            const isAuthorized = isGlobalAdmin || isServerOwner || (hasAdminRole && hasLinkedApiKey);

            if (interaction.commandName === 'set_admin_role') {
                if (!isGlobalAdmin && !isServerOwner) {
                    const errEmbed = new EmbedBuilder().setColor(0xEF4444).setDescription(`${EMOJI_CROSS} Only the Server Owner or Global Admin can assign the Admin Role.`);
                    return interaction.reply({ embeds: [errEmbed], ephemeral: true });
                }
                const modal = new ModalBuilder().setCustomId("modal_setadminrole").setTitle('Set Admin Role');
                modal.addComponents(new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('roleId').setLabel("Discord Role ID").setStyle(TextInputStyle.Short).setRequired(true)));
                return await interaction.showModal(modal).catch(console.error);
            }
            
            if (!isAuthorized) {
                const errEmbed = new EmbedBuilder()
                    .setColor(0xEF4444)
                    .setTitle(`${EMOJI_CROSS} Unauthorized`)
                    .setDescription("You must be the **Server Owner**, or have the designated **Admin Role** with a valid linked **API Key** (`/login`) to use this command.");
                return interaction.reply({ embeds: [errEmbed], ephemeral: true });
            }

            if (interaction.commandName === 'setup_panel') {
                const row = buildProjectSelect("selectproj_setuppanel", interaction, db);
                if (!row) return interaction.reply({ content: "You don't have any projects.", ephemeral: true });
                return interaction.reply({ content: "Please select a project for the panel:", components: [row], ephemeral: true });
            }

            if (interaction.commandName === 'create_giveaway') {
                const row = buildProjectSelect("selectproj_giveaway", interaction, db);
                if (!row) return interaction.reply({ content: "You don't have any projects.", ephemeral: true });
                return interaction.reply({ content: "Please select a project for the giveaway:", components: [row], ephemeral: true });
            }

            if (interaction.commandName === 'generate_key') {
                const row = buildProjectSelect("selectproj_genkey", interaction, db);
                if (!row) return interaction.reply({ content: "You don't have any projects.", ephemeral: true });
                return interaction.reply({ content: "Please select a project to generate keys for:", components: [row], ephemeral: true });
            }

            if (interaction.commandName === 'clear_keys') {
                const row = buildProjectSelect("selectproj_clearkeys", interaction, db);
                if (!row) return interaction.reply({ content: "You don't have any projects.", ephemeral: true });
                return interaction.reply({ content: "Please select a project to clear keys from:", components: [row], ephemeral: true });
            }

            if (interaction.commandName === 'user_info') {
                const row = buildProjectSelect("selectproj_userinfo", interaction, db);
                if (!row) return interaction.reply({ content: "You don't have any projects.", ephemeral: true });
                return interaction.reply({ content: "Please select a project to view the user's info:", components: [row], ephemeral: true });
            }

            if (interaction.commandName === 'reset_hwid') {
                const modal = new ModalBuilder().setCustomId("modal_resethwid").setTitle('Reset User HWID');
                modal.addComponents(new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('hwidKey').setLabel("The HWID Key").setStyle(TextInputStyle.Short).setRequired(true)));
                return await interaction.showModal(modal).catch(console.error);
            }

            if (interaction.commandName === 'extend_key') {
                const modal = new ModalBuilder().setCustomId("modal_extendkey").setTitle('Extend User Key');
                modal.addComponents(
                    new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('hwidKey').setLabel("The HWID Key").setStyle(TextInputStyle.Short).setRequired(true)),
                    new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('days').setLabel("Days to Add").setStyle(TextInputStyle.Short).setRequired(true))
                );
                return await interaction.showModal(modal).catch(console.error);
            }

            if (interaction.commandName === 'revoke_key') {
                const modal = new ModalBuilder().setCustomId("modal_revokekey").setTitle('Revoke User Key');
                modal.addComponents(new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('hwidKey').setLabel("The HWID Key to delete").setStyle(TextInputStyle.Short).setRequired(true)));
                return await interaction.showModal(modal).catch(console.error);
            }
        }

        if (interaction.isStringSelectMenu()) {
            const parts = interaction.customId.split('_');
            const prefix = parts;
            
            if (prefix === 'selectproj') {
                const action = parts;
                const projectId = interaction.values;
                const db = readDB();
                const project = db.projects.find(p => p.id === projectId);

                if (!project) return interaction.update({ content: "Project not found.", components: [] });

                if (action === 'setuppanel') {
                    try {
                        const modal = new ModalBuilder().setCustomId(`modal_setuppanel_${projectId}`).setTitle('Setup Panel Settings');
                        modal.addComponents(new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('roleId').setLabel("Customer Role ID (Optional)").setStyle(TextInputStyle.Short).setRequired(false)));
                        return await interaction.showModal(modal);
                    } catch (e) { console.error(e); }
                }

                if (action === 'giveaway') {
                    try {
                        const modal = new ModalBuilder().setCustomId(`modal_giveaway_${projectId}`).setTitle('Giveaway Settings');
                        modal.addComponents(
                            new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('winners').setLabel("Number of Winners").setStyle(TextInputStyle.Short).setRequired(true)),
                            new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('keyDays').setLabel("Key Duration (Days)").setStyle(TextInputStyle.Short).setRequired(true)),
                            new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('durationMins').setLabel("Giveaway Duration (Minutes)").setStyle(TextInputStyle.Short).setRequired(true))
                        );
                        return await interaction.showModal(modal);
                    } catch (e) { console.error(e); }
                }

                if (action === 'genkey') {
                    try {
                        const modal = new ModalBuilder().setCustomId(`modal_genkey_${projectId}`).setTitle('Generate Keys');
                        modal.addComponents(
                            new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('days').setLabel("Duration in Days").setStyle(TextInputStyle.Short).setRequired(true)),
                            new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('amount').setLabel("Amount of Keys (Max 1000)").setStyle(TextInputStyle.Short).setRequired(true))
                        );
                        return await interaction.showModal(modal);
                    } catch (e) { console.error(e); }
                }

                if (action === 'userinfo') {
                    try {
                        const modal = new ModalBuilder().setCustomId(`modal_userinfo_${projectId}`).setTitle('Lookup User');
                        modal.addComponents(new ActionRowBuilder().addComponents(new TextInputBuilder().setCustomId('userId').setLabel("Discord User ID").setStyle(TextInputStyle.Short).setRequired(true)));
                        return await interaction.showModal(modal);
                    } catch (e) { console.error(e); }
                }

                if (action === 'clearkeys') {
                    const initialLength = project.hwidKeys ? project.hwidKeys.length : 0;
                    if (project.hwidKeys) {
                        project.hwidKeys = project.hwidKeys.filter(k => {
                            const isUnused = !k.userId;
                            const isExpired = Date.now() > k.expiresAt;
                            return !isUnused && !isExpired; 
                        });
                    }
                    writeDB(db);
                    const removed = initialLength - (project.hwidKeys ? project.hwidKeys.length : 0);
                    
                    const okEmbed = new EmbedBuilder().setColor(0xF59E0B).setDescription(`${EMOJI_BROOM} **Cleared ${removed} unused or expired keys** from ${project.name}.`);
                    return interaction.update({ content: "", embeds: [okEmbed], components: [] });
                }
            }
        }

        if (interaction.isButton()) {
            const parts = interaction.customId.split('_');
            const prefix = parts;

            if (prefix === 'authgw') {
                try {
                    await interaction.deferReply({ ephemeral: true });
                    const gwId = parts.slice(2).join('_');
                    const db = readDB();
                    const gw = db.giveaways.find(g => g.id === gwId);
                    
                    if (!gw) return interaction.editReply({ content: "Giveaway not found or expired." });
                    if (gw.ended) return interaction.editReply({ content: "Giveaway has ended." });

                    const project = db.projects.find(p => p.id === gw.projectId);
                    if (!project) return interaction.editReply({ content: "Project not found." });

                    if (project.discordConfig && project.discordConfig.roleId) {
                        try {
                            const member = await interaction.guild.members.fetch(interaction.user.id);
                            if (member && member.roles.cache.has(project.discordConfig.roleId)) {
                                return interaction.editReply({ content: "You already have the customer role for this project, so you cannot enter!" });
                            }
                        } catch(e) {}
                    }

                    if (gw.participants.includes(interaction.user.id)) {
                        return interaction.editReply({ content: "You have already entered this giveaway!" });
                    }

                    gw.participants.push(interaction.user.id);
                    writeDB(db);
                    return interaction.editReply({ content: `${EMOJI_TADA} You have successfully entered the giveaway!` });
                } catch(e) {
                    return interaction.editReply({ content: "An error occurred while joining." });
                }
            }

            if (prefix === 'auth') {
                const action = parts;
                const projectId = parts.slice(2).join('_');
                
                const db = readDB();
                const project = db.projects.find(p => p.id === projectId);
                if (!project) return interaction.reply({ content: "Project no longer exists.", ephemeral: true });

                if (action === 'redeem') {
                    const modal = new ModalBuilder().setCustomId(`modal_redeem_${projectId}`).setTitle('Redeem License Key');
                    const keyInput = new TextInputBuilder().setCustomId('keyInput').setLabel("Enter your HWID Key").setStyle(TextInputStyle.Short).setRequired(true);
                    modal.addComponents(new ActionRowBuilder().addComponents(keyInput));
                    return await interaction.showModal(modal).catch(console.error);
                }

                await interaction.deferReply({ ephemeral: true });

                const userKey = (project.hwidKeys || []).find(k => k.userId === interaction.user.id);
                if (!userKey) return interaction.editReply({ content: "You do not have a claimed key for this project." });

                const loaderCode = `getgenv().script_key = "${userKey.key}"\nloadstring(game:HttpGet("${HOST_URL}/loader/${projectId}"))()`;

                if (action === 'getscriptembed') {
                    const scriptEmbed = new EmbedBuilder()
                        .setTitle('Your Script Loader')
                        .setDescription(`\`\`\`lua\n${loaderCode}\n\`\`\``)
                        .setColor(0x4F6CEE)
                        .setFooter({ text: "Do not share your key with anyone." });
                    return interaction.editReply({ embeds: [scriptEmbed] });
                }

                if (action === 'getscriptnoembed') {
                    return interaction.editReply({ content: loaderCode });
                }

                if (action === 'reset') {
                    const cooldownMs = (project.hwidResetCooldown || 24) * 60 * 60 * 1000;
                    if (Date.now() - (userKey.lastReset || 0) < cooldownMs) {
                        const hoursLeft = Math.ceil((cooldownMs - (Date.now() - userKey.lastReset)) / 3600000);
                        return interaction.editReply({ content: `Cooldown active. You can reset your HWID again in ${hoursLeft} hours.` });
                    }
                    userKey.hwid = null;
                    userKey.ip = null;
                    userKey.lastReset = Date.now();
                    writeDB(db);
                    return interaction.editReply({ content: `${EMOJI_CHECK} Your HWID has been successfully reset. Run the script again to bind your new device.` });
                }

                if (action === 'stats') {
                    const daysLeft = Math.max(0, Math.ceil((userKey.expiresAt - Date.now()) / (1000 * 60 * 60 * 24)));
                    const statusStr = userKey.hwid ? "Locked to Device" : "Unbound";
                    const statsEmbed = new EmbedBuilder()
                        .setTitle("Account Statistics")
                        .setColor(0x4F6CEE)
                        .addFields(
                            { name: "Project", value: project.name, inline: true },
                            { name: "Days Remaining", value: `${daysLeft} Days`, inline: true },
                            { name: "HWID Status", value: statusStr, inline: false }
                        );
                    return interaction.editReply({ embeds: [statsEmbed] });
                }
            }
        }

        if (interaction.isModalSubmit()) {
            const parts = interaction.customId.split('_');
            const prefix = parts.shift();
            const action = parts.shift();
            
            if (prefix !== 'modal') return;

            const db = readDB();

            if (action === 'setadminrole') {
                await interaction.deferReply({ ephemeral: true });
                const roleId = interaction.fields.getTextInputValue('roleId').trim();
                if (!db.guildConfigs) db.guildConfigs = {};
                if (!db.guildConfigs[interaction.guildId]) db.guildConfigs[interaction.guildId] = {};
                db.guildConfigs[interaction.guildId].adminRoleId = roleId;
                writeDB(db);
                const okEmbed = new EmbedBuilder().setColor(0x10B981).setDescription(`${EMOJI_CHECK} Admin Role successfully set to <@&${roleId}>.`);
                return interaction.editReply({ embeds: [okEmbed] });
            }

            if (action === 'resethwid') {
                await interaction.deferReply({ ephemeral: true });
                const keyStr = interaction.fields.getTextInputValue('hwidKey').trim();
                let found = false;
                db.projects.forEach(p => {
                    const k = (p.hwidKeys || []).find(x => x.key === keyStr);
                    if (k) { k.hwid = null; k.ip = null; k.lastReset = Date.now(); found = true; }
                });
                if (found) { 
                    writeDB(db); 
                    const okEmbed = new EmbedBuilder().setColor(0x10B981).setDescription(`${EMOJI_CHECK} HWID successfully reset for that key.`);
                    return interaction.editReply({ embeds: [okEmbed] });
                }
                return interaction.editReply({ content: "Key not found." });
            }

            if (action === 'extendkey') {
                await interaction.deferReply({ ephemeral: true });
                const keyStr = interaction.fields.getTextInputValue('hwidKey').trim();
                const days = parseInt(interaction.fields.getTextInputValue('days').trim());
                if (isNaN(days)) return interaction.editReply({ content: "Invalid number of days." });

                let found = false;
                db.projects.forEach(p => {
                    const k = (p.hwidKeys || []).find(x => x.key === keyStr);
                    if (k) { k.expiresAt += (days * 24 * 60 * 60 * 1000); k.roleRemoved = false; found = true; }
                });
                if (found) { 
                    writeDB(db); 
                    const okEmbed = new EmbedBuilder().setColor(0x10B981).setDescription(`${EMOJI_CHECK} Key successfully extended by **${days}** days.`);
                    return interaction.editReply({ embeds: [okEmbed] }); 
                }
                return interaction.editReply({ content: "Key not found." });
            }

            if (action === 'revokekey') {
                await interaction.deferReply({ ephemeral: true });
                const keyStr = interaction.fields.getTextInputValue('hwidKey').trim();
                let found = false;
                db.projects.forEach(async p => {
                    const idx = (p.hwidKeys || []).findIndex(x => x.key === keyStr);
                    if (idx !== -1) { 
                        const k = p.hwidKeys[idx];
                        if (k.userId && p.discordConfig && p.discordConfig.roleId) {
                            try {
                                const guild = await client.guilds.fetch(p.discordConfig.guildId);
                                const member = await guild.members.fetch(k.userId);
                                await member.roles.remove(p.discordConfig.roleId);
                            } catch (e) {}
                        }
                        p.hwidKeys.splice(idx, 1); 
                        found = true; 
                    }
                });
                if (found) { 
                    writeDB(db); 
                    const okEmbed = new EmbedBuilder().setColor(0xEF4444).setDescription(`${EMOJI_TRASH} Key successfully revoked and deleted.`);
                    return interaction.editReply({ embeds: [okEmbed] }); 
                }
                return interaction.editReply({ content: "Key not found." });
            }

            if (action === 'userinfo') {
                await interaction.deferReply({ ephemeral: true });
                const projectId = parts.join('_');
                const project = db.projects.find(p => p.id === projectId);
                if (!project) return interaction.editReply({ content: "Project no longer exists." });

                const targetUserId = interaction.fields.getTextInputValue('userId').trim();
                const userKey = (project.hwidKeys || []).find(k => k.userId === targetUserId);
                if (!userKey) {
                    const errEmbed = new EmbedBuilder().setColor(0xEF4444).setDescription(`${EMOJI_CROSS} <@${targetUserId}> does not have a key for this project.`);
                    return interaction.editReply({ embeds: [errEmbed] });
                }

                const daysLeft = Math.max(0, Math.ceil((userKey.expiresAt - Date.now()) / (1000 * 60 * 60 * 24)));
                const statusStr = userKey.hwid ? `Locked to Device (${userKey.hwid.substring(0, 8)}...)` : "Unbound";

                let targetUsername = "User";
                try {
                    const tUser = await client.users.fetch(targetUserId);
                    targetUsername = tUser.username;
                } catch(e) {}

                const infoEmbed = new EmbedBuilder()
                    .setTitle(`User Info: ${targetUsername}`)
                    .setColor(0x4F6CEE)
                    .addFields(
                        { name: "Project", value: project.name, inline: true },
                        { name: "Key", value: `||${userKey.key}||`, inline: true },
                        { name: "Days Left", value: `${daysLeft} Days`, inline: true },
                        { name: "HWID Status", value: statusStr, inline: true }
                    );
                return interaction.editReply({ embeds: [infoEmbed] });
            }

            if (action === 'setuppanel') {
                await interaction.deferReply({ ephemeral: true });
                const projectId = parts.join('_');
                const project = db.projects.find(p => p.id === projectId);
                if (!project) return interaction.editReply({ content: "Project no longer exists." });

                const roleId = interaction.fields.getTextInputValue('roleId').trim();
                project.discordConfig = { guildId: interaction.guildId, roleId: roleId, channelId: interaction.channelId };
                writeDB(db);
                
                const embed = new EmbedBuilder()
                    .setTitle(`${project.name} - Script Panel`)
                    .setColor(0x4F6CEE)
                    .setDescription("**Script:** Custom Loader\n\nUse the buttons below to manage your account:\n• Redeem your key to link your Discord account\n• Get the script download code\n• Reset your hardware ID\n• View your account statistics");

                const row1 = new ActionRowBuilder().addComponents(
                    new ButtonBuilder().setCustomId(`auth_redeem_${project.id}`).setLabel('Redeem Key').setEmoji("🔑").setStyle(ButtonStyle.Success),
                    new ButtonBuilder().setCustomId(`auth_stats_${project.id}`).setLabel('Status').setEmoji("📊").setStyle(ButtonStyle.Secondary)
                );
                const row2 = new ActionRowBuilder().addComponents(
                    new ButtonBuilder().setCustomId(`auth_getscriptembed_${project.id}`).setLabel('Copy Script').setEmoji("📥").setStyle(ButtonStyle.Primary),
                    new ButtonBuilder().setCustomId(`auth_getscriptnoembed_${project.id}`).setLabel('Copy Script (No Embed)').setEmoji("📋").setStyle(ButtonStyle.Primary)
                );
                const row3 = new ActionRowBuilder().addComponents(
                    new ButtonBuilder().setCustomId(`auth_reset_${project.id}`).setLabel('Reset HWID').setEmoji("🔄").setStyle(ButtonStyle.Danger)
                );

                const channel = await client.channels.fetch(interaction.channelId).catch(() => null);
                if (!channel) return interaction.editReply({ content: "❌ Could not access the channel." });

                await channel.send({ embeds: [embed], components: [row1, row2, row3] }).catch(() => {});
                
                const okEmbed = new EmbedBuilder().setColor(0x10B981).setDescription(`${EMOJI_CHECK} Panel deployed successfully.`);
                return interaction.editReply({ embeds: [okEmbed] });
            }

            if (action === 'genkey') {
                await interaction.deferReply({ ephemeral: true });
                const projectId = parts.join('_');
                const project = db.projects.find(p => p.id === projectId);
                if (!project) return interaction.editReply({ content: "Project no longer exists." });

                const days = parseInt(interaction.fields.getTextInputValue('days'));
                const amount = parseInt(interaction.fields.getTextInputValue('amount'));
                if (isNaN(days) || isNaN(amount)) return interaction.editReply({ content: "Invalid numbers provided." });

                const expiresAt = Date.now() + (days * 24 * 60 * 60 * 1000);
                if (!project.hwidKeys) project.hwidKeys = [];
                
                const generated = [];
                for(let i=0; i<amount; i++) {
                    const newKey = crypto.randomBytes(12).toString('hex').toLowerCase();
                    generated.push(newKey);
                    project.hwidKeys.push({ key: newKey, createdAt: Date.now(), expiresAt: expiresAt, userId: null, hwid: null, ip: null, roleRemoved: false });
                }
                writeDB(db);

                const okEmbed = new EmbedBuilder()
                    .setTitle(`✅ Generated ${amount} Key(s)`)
                    .setColor(0x10B981)
                    .addFields(
                        { name: 'Project', value: project.name, inline: true },
                        { name: 'Duration', value: `${days} Days`, inline: true }
                    );

                if (amount > 15) {
                    const buffer = Buffer.from(generated.join('\n'), 'utf-8');
                    const attachment = new AttachmentBuilder(buffer, { name: 'keys.txt' });
                    okEmbed.setDescription("Keys have been attached in the text file below.");
                    return interaction.editReply({ embeds: [okEmbed], files: [attachment] });
                } else {
                    const keyList = generated.map(k => `\`${k}\``).join('\n');
                    okEmbed.setDescription(`**Keys:**\n${keyList}`);
                    return interaction.editReply({ embeds: [okEmbed] });
                }
            }

            if (action === 'giveaway') {
                await interaction.deferReply({ ephemeral: true });
                const projectId = parts.join('_');
                const project = db.projects.find(p => p.id === projectId);
                if (!project) return interaction.editReply({ content: "Project no longer exists." });

                const winners = parseInt(interaction.fields.getTextInputValue('winners'));
                const keyDays = parseInt(interaction.fields.getTextInputValue('keyDays'));
                const durationMins = parseInt(interaction.fields.getTextInputValue('durationMins'));

                if (isNaN(winners) || isNaN(keyDays) || isNaN(durationMins)) {
                    return interaction.editReply({ content: "Invalid numbers provided." });
                }

                const gwId = crypto.randomBytes(8).toString('hex');
                const endsAt = Date.now() + (durationMins * 60 * 1000);
                const timestamp = Math.floor(endsAt / 1000);

                const embed = new EmbedBuilder()
                    .setTitle(`🎉 **${project.name} Script Giveaway!** 🎉`)
                    .setColor(0x4F6CEE)
                    .setDescription(`**Prize:** ${winners}x Key(s) (${keyDays} Days)\n**Ends:** <t:${timestamp}:R> (<t:${timestamp}:f>)\n\nClick the button below to enter!`)
                    .setFooter({ text: "Luau-Auth Giveaways" });

                const rowBtn = new ActionRowBuilder().addComponents(
                    new ButtonBuilder().setCustomId(`authgw_join_${gwId}`).setLabel('Join Giveaway').setEmoji("🎉").setStyle(ButtonStyle.Success)
                );

                const channel = await client.channels.fetch(interaction.channelId).catch(() => null);
                if (!channel) return interaction.editReply({ content: `❌ Could not access the channel.` });

                const msg = await channel.send({ embeds: [embed], components: [rowBtn] });

                db.giveaways.push({
                    id: gwId,
                    messageId: msg.id,
                    channelId: msg.channelId,
                    guildId: msg.guildId,
                    projectId: project.id,
                    winnersCount: winners,
                    keyDays: keyDays,
                    endsAt: endsAt,
                    ended: false,
                    participants: []
                });
                writeDB(db);

                return interaction.editReply({ content: `✅ Giveaway deployed successfully!` });
            }

        }
    } catch (globalError) {
        console.error("Global Interaction Error:", globalError);
        try {
            if (interaction.isRepliable() && !interaction.replied && !interaction.deferred) {
                await interaction.reply({ content: "An error occurred while processing this command.", ephemeral: true });
            } else if (interaction.deferred && !interaction.replied) {
                await interaction.editReply({ content: "An error occurred while processing this command." });
            }
        } catch (e) {}
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`[OK] Web Server is running on port ${PORT}`);
});

if (DISCORD_BOT_TOKEN) {
    console.log("Attempting to log in to Discord...");
    client.login(DISCORD_BOT_TOKEN).then(() => {
        console.log(`[OK] Discord Bot Successfully Logged In as ${client.user.tag}`);
    }).catch((err) => {
        console.error("[ERROR] DISCORD BOT CRASHED ON STARTUP:", err.message);
    });
}
