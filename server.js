const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// In a real application, you would replace this mock database
// with a real database connection (like PostgreSQL, MongoDB, or Firebase)
// where the Sanctuary panel saves the data.
const database = {
    "your_project_id_here": {
        "your_script_id_here": {
            status: "Active",
            code: "-- Custom Lua Code\nprint('Script loaded successfully via Sanctuary API!')"
        }
    }
};

// Route that handles the loadstring request from Roblox: originalurl.com/projectid/scriptid
app.get('/:projectId/:scriptId', (req, res) => {
    const { projectId, scriptId } = req.params;

    // Look up the project and script in the database
    const project = database[projectId];
    
    if (project && project[scriptId]) {
        const script = project[scriptId];
        
        // Check the toggle switch status
        if (script.status === 'Active') {
            // Must return as text/plain so Roblox loadstring() executes it correctly
            res.type('text/plain');
            res.send(script.code);
        } else {
            res.status(403).send('-- Error: This script is currently disabled by the developer.');
        }
    } else {
        res.status(404).send('-- Error: Script or Project not found.');
    }
});

// Health check endpoint for Railway
app.get('/', (req, res) => {
    res.send('Sanctuary Script API is running online.');
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Sanctuary API is successfully running on port ${PORT}`);
});
