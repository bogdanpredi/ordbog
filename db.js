const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Create or connect to the SQLite database
const dbPath = path.resolve(__dirname, 'db', 'vocabulary.db');  // Adjust path if needed
console.log(`Attempting to connect to database at: ${dbPath}`);  // Log the path of the database file

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database:', err.message);  // Log error if connection fails
    } else {
        console.log('Connected to the SQLite database.');        // Log success message
    }
});

// Create the table if it doesn't exist
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS words (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        danish TEXT,
        translation TEXT,
        examples TEXT,
        synonym TEXT,
        meaning TEXT,
        wordclass TEXT
    )`);
});

module.exports = db;
