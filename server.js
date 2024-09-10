const express = require('express');
const session = require('express-session'); // For session management
const bodyParser = require('body-parser');
const multer = require('multer');
const fs = require('fs');
const csvParser = require('csv-parser');
const path = require('path');
const db = require('./db');
const app = express();
const { Readable } = require('stream');
const bcrypt = require('bcryptjs');

// Serve static files from 'public' folder
app.use(express.static('public'));
app.use(bodyParser.json());

const upload = multer({ dest: 'uploads/' });

// Route to add a new user (for example purposes)
app.post('/api/add-user', async (req, res) => {
    const { username, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);  // Hash the password

        db.run(
            'INSERT INTO users (username, password) VALUES (?, ?)',
            [username, hashedPassword],
            (err) => {
                if (err) {
                    return res.status(500).json({ message: 'Error adding user', error: err.message });
                }
                res.json({ message: 'User added successfully' });
            }
        );
    } catch (err) {
        console.error('Error creating user:', err);
        res.status(500).json({ message: 'Error creating user' });
    }
});

// Use session to track login status
app.use(session({
    secret: 'your-secret-key', // Use a secure key for signing the session ID cookie
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },  // Use `true` if you're using HTTPS
}));

// Mock user data (replace with a real database check)
const users = [
    { username: 'admin', password: 'password123' }
];

// Login endpoint
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            console.error('Error retrieving user:', err.message);
            return res.status(500).json({ message: 'Error retrieving user' });
        }

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Check if the user is blocked
        if (user.is_blocked) {
            return res.status(403).json({ message: 'Your account is blocked due to too many failed login attempts' });
        }

        // Compare the hashed password with the provided password
        const isPasswordCorrect = await bcrypt.compare(password, user.password);

        if (!isPasswordCorrect) {
            // Increment failed attempts
            db.run(
                'UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?',
                [username],
                function (err) {
                    if (err) {
                        return res.status(500).json({ message: 'Error updating failed attempts' });
                    }

                    // If failed attempts are 3 or more, block the user
                    if (user.failed_attempts + 1 >= 3) {
                        db.run('UPDATE users SET is_blocked = 1 WHERE username = ?', [username]);
                        return res.status(403).json({ message: 'Your account is blocked due to too many failed login attempts' });
                    }

                    return res.status(401).json({ message: 'Invalid credentials' });
                }
            );
        } else {
            // Reset failed attempts on successful login
            db.run('UPDATE users SET failed_attempts = 0 WHERE username = ?', [username], (err) => {
                if (err) {
                    return res.status(500).json({ message: 'Error resetting failed attempts' });
                }

                req.session.loggedIn = true;  // Set session to indicate logged in
                req.session.username = username;  // Optionally store the username in the session
                res.json({ message: 'Login successful' });
            });
        }
    });
});

// Endpoint to unblock user
app.post('/api/unblock-user', (req, res) => {
    const { username } = req.body;

    db.run(
        'UPDATE users SET failed_attempts = 0, is_blocked = 0 WHERE username = ?',
        [username],
        (err) => {
            if (err) {
                return res.status(500).json({ message: 'Error unblocking user' });
            }
            res.json({ message: 'User unblocked successfully' });
        }
    );
});


// Middleware to check login status
function isAuthenticated(req, res, next) {
    if (req.session.loggedIn) {
        return next();  // Continue if the user is logged in
    } else {
        res.redirect('/login.html');  // Redirect to login page if not logged in
    }
}

// Serve protected pages only if the user is authenticated
app.get('/add-word.html', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/public/add-word.html');
});

app.get('/upload-csv.html', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/public/upload-csv.html');
});

app.get('/parse-csv.html', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/public/parse-csv.html');
});

app.get('/manage-entries.html', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/public/manage-entries.html');
});

// Endpoint to add a new word
app.post('/api/words', (req, res) => {
    const { danish, translation, examples, synonym, meaning, wordclass } = req.body;

    if (!danish || !translation) {
        return res.status(400).json({ error: 'Danish and translation fields are required' });
    }

    db.run(
        'INSERT INTO words (danish, translation, examples, synonym, meaning, wordclass) VALUES (?, ?, ?, ?, ?, ?)',
        [danish, translation, examples, synonym, meaning, wordclass],
        function (err) {
            if (err) {
                console.error('Error adding word:', err.message);
                res.status(500).json({ error: err.message });
            } else {
                res.json({ id: this.lastID });
            }
        }
    );
});

// Route to fetch paginated words in the order they were added
app.get('/api/words', (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;
    
    // Fetch words in the order they were added (by id)
    db.all('SELECT * FROM words ORDER BY id ASC LIMIT ? OFFSET ?', [limit, offset], (err, rows) => {
        if (err) {
            console.error('Error fetching paginated words:', err);
            return res.status(500).json({ message: 'Error fetching paginated words' });
        }
        db.get('SELECT COUNT(*) AS count FROM words', (err, row) => {
            if (err) {
                return res.status(500).json({ message: 'Error fetching word count' });
            }
            res.json({ words: rows, total: row.count });
        });
    });
});

// Route to fetch all words for searching
app.get('/api/all-words', (req, res) => {
    db.all('SELECT * FROM words ORDER BY danish COLLATE NOCASE', (err, rows) => {
        if (err) {
            console.error('Error fetching all words:', err);
            return res.status(500).json({ message: 'Error fetching all words' });
        }
        res.json({ words: rows });
    });
});



// Endpoint to handle pasted CSV text
app.post('/api/parse-csv', (req, res) => {
    const { csvText } = req.body;

    console.log('Received CSV Text:', csvText);  // Log the received CSV text for debugging

    if (!csvText || csvText.trim() === "") {
        return res.status(400).json({ message: 'No CSV text provided' });
    }

    const results = [];

    const stream = Readable.from([csvText]);

    stream
        .pipe(csvParser({
            skipEmptyLines: true,    // Skip empty lines
            separator: ',',          // Handle comma-separated values
            headers: false,          // Treat all rows as data (no header row)
        }))
        .on('data', (row) => {
            // Assuming your CSV has this order: Danish, Translation, Examples, Synonym, Meaning, Class
            const [danish, translation, examples, synonym, meaning, wordclass] = Object.values(row);

            console.log('Parsed row:', { danish, translation, examples, synonym, meaning, wordclass });  // Log parsed row

            results.push({
                danish: danish || '',
                translation: translation || '',
                examples: examples || '',
                synonym: synonym || '',
                meaning: meaning || '',
                wordclass: wordclass || '',
            });
        })
        .on('end', () => {
            if (results.length > 0) {
                console.log('All parsed rows:', results);  // Log all parsed rows

                // Insert the parsed data into the database
                const insertStmt = db.prepare(
                    'INSERT INTO words (danish, translation, examples, synonym, meaning, wordclass) VALUES (?, ?, ?, ?, ?, ?)'
                );

                results.forEach((row) => {
                    insertStmt.run(
                        row.danish,
                        row.translation,
                        row.examples,
                        row.synonym,
                        row.meaning,
                        row.wordclass,
                        function (err) {
                            if (err) {
                                console.error('Error inserting row:', err.message);
                                return res.status(500).json({ message: 'Error inserting row', error: err.message });
                            }
                        }
                    );
                });

                insertStmt.finalize(() => {
                    res.json({ message: 'CSV data inserted successfully' });
                });
            } else {
                res.status(400).json({ message: 'No data to insert' });
            }
        })
        .on('error', (error) => {
            console.error('Error parsing CSV:', error.message);
            res.status(500).json({ message: 'Error parsing CSV', error: error.message });
        });
});

// Endpoint to upload and process CSV
app.post('/api/upload-csv', upload.single('csvFile'), (req, res) => {
    const csvFilePath = req.file.path;

    const results = [];

    fs.createReadStream(csvFilePath)
        .pipe(csvParser())
        .on('data', (data) => {
            results.push({
                danish: data.Danish || '',   // Empty cells will be stored as empty strings
                translation: data.Translation || '',
                examples: data.Examples || '',
                synonym: data.Synonym || '',
                meaning: data.Meaning || '',
                wordclass: data.Class || ''
            });
        })
        .on('end', () => {
            if (results.length > 0) {
                results.sort((a, b) => a.danish.localeCompare(b.danish));

                const insertStmt = db.prepare(
                    'INSERT INTO words (danish, translation, examples, synonym, meaning, wordclass) VALUES (?, ?, ?, ?, ?, ?)'
                );

                results.forEach((row) => {
                    insertStmt.run(
                        row.danish,
                        row.translation,
                        row.examples,
                        row.synonym,
                        row.meaning,
                        row.wordclass,
                        function (err) {
                            if (err) {
                                console.error('Error inserting row:', err.message);
                            } else {
                                console.log(`Inserted row with id ${this.lastID}`);
                            }
                        }
                    );
                });

                insertStmt.finalize();
            }

            // Delete the uploaded CSV file after processing
            fs.unlinkSync(csvFilePath);

            // Redirect to index.html after successful upload
            res.redirect('/index.html');
        })
        .on('error', (error) => {
            console.error('Error processing CSV:', error);
            res.status(500).json({ message: 'Error processing CSV', error });
        });
});

// Route to update an entry
app.post('/api/words/:id', (req, res) => {
    const { id } = req.params;
    const { danish, translation, examples, synonym, meaning, wordclass } = req.body;

    const query = `UPDATE words SET danish = ?, translation = ?, examples = ?, synonym = ?, meaning = ?, wordclass = ? WHERE id = ?`;
    db.run(query, [danish, translation, examples, synonym, meaning, wordclass, id], function (err) {
        if (err) {
            return res.status(500).json({ error: 'Failed to update entry' });
        }
        res.json({ message: 'Entry updated successfully' });
    });
});

// Route to delete an individual entry
app.delete('/api/words/:id', (req, res) => {
    const { id } = req.params;

    db.run('DELETE FROM words WHERE id = ?', [id], function (err) {
        if (err) {
            return res.status(500).json({ error: 'Failed to delete entry' });
        }
        res.json({ message: 'Entry deleted successfully' });
    });
});

// Route to delete all entries
app.delete('/api/words', (req, res) => {
    db.run('DELETE FROM words', (err) => {
        if (err) {
            return res.status(500).json({ message: 'Error deleting all entries' });
        }
        res.json({ message: 'All entries deleted successfully' });
    });
});

// Logout route
app.get('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ message: 'Logout failed' });
        }
        res.json({ message: 'Logged out successfully' });
    });
});

// Route to fetch paginated and searchable entries
app.get('/api/manage-entries', (req, res) => {
    const page = parseInt(req.query.page) || 1;  // Get page from query string
    const limit = 10;  // Set the number of entries per page
    const search = req.query.search || '';  // Get search term
    const offset = (page - 1) * limit;

    const query = `SELECT * FROM words WHERE danish LIKE ? ORDER BY id ASC LIMIT ? OFFSET ?`;
    const countQuery = `SELECT COUNT(*) AS count FROM words WHERE danish LIKE ?`;

    // Perform the paginated query
    db.all(query, [`%${search}%`, limit, offset], (err, rows) => {
        if (err) {
            console.error('Error fetching entries:', err);
            return res.status(500).json({ message: 'Error fetching entries' });
        }

        // Count the total entries for pagination
        db.get(countQuery, [`%${search}%`], (err, row) => {
            if (err) {
                console.error('Error fetching total count:', err);
                return res.status(500).json({ message: 'Error fetching total count' });
            }
            res.json({ words: rows, total: row.count });
        });
    });
});

app.get('/test', (req, res) => {
    res.send('Test route is working!');
});

// Create the users table if it doesn't exist
db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        failed_attempts INTEGER DEFAULT 0,
        is_blocked INTEGER DEFAULT 0
    )
`, (err) => {
    if (err) {
        console.error('Error creating users table:', err.message);
    } else {
        console.log('Users table created or already exists.');
    }
});

// Middleware to log session and request information for every request
app.use((req, res, next) => {
    console.log('Request URL:', req.url);
    console.log('Logged in:', req.session.loggedIn);
    console.log('Session Data:', req.session);
    next();
});

// Route to get the total number of entries in the database
app.get('/api/word-count', (req, res) => {
    db.get('SELECT COUNT(*) AS count FROM words', (err, row) => {
        if (err) {
            console.error('Error fetching word count:', err);
            return res.status(500).json({ message: 'Error fetching word count' });
        }
        res.json({ count: row.count });
    });
});

// Start the server
app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
