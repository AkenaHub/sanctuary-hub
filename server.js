const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// This line is super important! It tells the server to show your HTML file
app.use(express.static(__dirname));

const database = {
    "your_project_id_here": {
        "your_script_id_here": {
            status: "Active",
            code: "-- Custom Lua Code\nprint('Script loaded successfully via Sanctuary API!')"
        }
    }
};

app.get('/:projectId/:scriptId', (req, res) => {
    const { projectId, scriptId } = req.params;
    const project = database[projectId];
    
    if (project && project[scriptId]) {
        const script = project[scriptId];
        if (script.status === 'Active') {
            res.type('text/plain');
            res.send(script.code);
        } else {
            res.status(403).send('-- Error: This script is currently disabled by the developer.');
        }
    } else {
        res.status(404).send('-- Error: Script or Project not found.');
    }
});

// Update the bottom part to look exactly like this for Railway:
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Sanctuary API is successfully running on port ${PORT}`);
});
