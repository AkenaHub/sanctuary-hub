const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());

// Increase JSON limit so large Lua files can be uploaded without crashing
app.use(express.json({ limit: '50mb' })); 

// Serves your frontend UI when people visit the main link
app.use(express.static(__dirname));

const dbPath = path.join(__dirname, 'database.json');

// --- Database Helpers ---
const readDB = () => {
    try {
        if (fs.existsSync(dbPath)) {
            return JSON.parse(fs.readFileSync(dbPath, 'utf8'));
        }
    } catch (err) {
        console.error("Error reading database:", err);
    }
    return { projects: [] }; 
};

const writeDB = (data) => {
    try {
        fs.writeFileSync(dbPath, JSON.stringify(data, null, 2));
    } catch (err) {
        console.error("Error saving database:", err);
    }
};

// --- Frontend Sync Endpoints ---
app.get('/api/sync', (req, res) => res.json(readDB()));

app.post('/api/sync', (req, res) => {
    writeDB(req.body);
    res.json({ success: true });
});

// --- RAW SCRIPT URL ENDPOINT ---
// URL Format: https://domain.com/raw/projectId/scriptId
app.get('/raw/:projectId/:scriptId', (req, res) => {
    const { projectId, scriptId } = req.params;
    const db = readDB();
    
    const project = db.projects.find(p => p.id === projectId);
    if (project) {
        const script = project.scripts.find(s => s.id === scriptId);
        if (script) {
            if (script.status === 'Active') {
                res.type('text/plain');
                return res.send(script.code || '-- Error: Uploaded script file was completely empty.');
            } else {
                return res.status(403).send('-- Error: This script is currently disabled by the developer.');
            }
        }
    }
    
    // Explicitly matched the error message you mentioned!
    res.status(404).send('-- Error: Script or Project not found.');
});

// --- CUSTOM LOADER URL ENDPOINT ---
// URL Format: https://domain.com/loader/projectId
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

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Sanctuary Hub API is successfully running on port ${PORT}`);
});
