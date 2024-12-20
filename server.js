const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const app = express();
const port = 3000;
const cors = require('cors');
app.use(cors()); // This allows requests from any origin
const session = require('express-session');
cookie: { secure: false}  // Set this only if your site is served over HTTPS

app.use(bodyParser.json());
app.use(express.static('public')); // Serve static files like login.html
app.use('/WST-Website', express.static('WST-website')); // Serve static files from "wst-website" folder


app.use(session({
    secret: 'yourSecretKey',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }  // use 'secure: true' if HTTPS
}));

app.use(express.json());

// Define routes after the session middleware


// Serve load.html as the default page when accessing the root URL
app.get('/', (req, res) => {
    console.log(__dirname + '/public/load.html'); // Check the path
    res.sendFile(__dirname + '/public/load.html');
});


// MySQL database connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root', // your MySQL username
    password: 'GARINBELLYJOE@2004', // your MySQL password
    database: 'belly' // your database name
});

db.connect((err) => {
    if (err) {
        console.error('Could not connect to the database:', err);
        return;
    }
    console.log('Connected to the database');
});


// User Login route (with user_id included in the response)
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Please provide both username and password' });
    }

    // Query the 'belly' table for the user credentials
    const query = 'SELECT * FROM belly WHERE username = ?';
    db.query(query, [username], (err, results) => {
        if (err) {
            // Database error
            res.status(500).json({ success: false, message: 'Database error' });
            return;
        }

        if (results.length > 0) {
            const user = results[0]; // Get the first matching user

            // Compare the entered password with the hashed password
            bcrypt.compare(password, user.password, (err, isMatch) => {
                if (err) {
                    return res.status(500).json({ success: false, message: 'Error comparing password' });
                }

                if (isMatch) {
                    req.session.user = { 
                        userId: user.user_id, 
                        username: user.username 
                    };
                    req.session.userId = results[0].id; // Store user ID in session
                    console.log("Session user data after setting:", req.session.user);  // Should show user data
                    res.json({ success: true, message: 'Login successful', redirectUrl: '/WST-Website/index.html' });
                } else {
                    // Invalid credentials
                    res.status(401).json({ success: false, message: 'Invalid login credentials' });
                }
            });
        } else {
            // User not found
            res.status(401).json({ success: false, message: 'User not found' });
        }
        console.log('Session user data:', req.session.user);
    });
});

// get user route
app.get('/get-user', (req, res) => {
    console.log('Fetching user data from session:', req.session.user);
    if (req.session.user) {
        res.status(200).json({
            success: true,
            username: req.session.user.username,
            userId: req.session.user.userId
        });
    } else {
        res.status(401).json({ success: false, message: 'Not logged in' });
    }
});

// Registration route (for users)
app.post('/register', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Please provide both username and password' });
    }

    // Check if the username already exists in the database
    const checkQuery = 'SELECT * FROM belly WHERE username = ?';
    db.query(checkQuery, [username], (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Database error' });
        }

        // If the username already exists, send a response to notify the user
        if (results.length > 0) {
            return res.status(400).json({ success: false, message: 'Username already exists' });
        }

        // If the username is available, hash the password and insert the user into the database
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                return res.status(500).json({ success: false, message: 'Error hashing password' });
            }

            // Generate a random 6-digit user ID (between 100000 and 999999)
            const userId = Math.floor(100000 + Math.random() * 900000);

            // Insert the new username, hashed password, and userId into the 'belly' table
            const query = 'INSERT INTO belly (user_id, username, password) VALUES (?, ?, ?)';
            db.query(query, [userId, username, hashedPassword], (err, results) => {
                if (err) {
                    console.error('Database error:', err);
                    res.status(500).json({ success: false, message: 'Database error', error: err.message });
                    return;
                }

                res.json({ success: true, message: 'Registration successful', userId: userId });
            });
        });
    });
});


// Admin Login
app.post('/admin/login', (req, res) => {
    console.log("Admin login request received");
    const { admin_name, admin_password } = req.body;
    console.log("Admin Name:", admin_name, "Admin Password:", admin_password);

    if (!admin_name || !admin_password) {
        console.log("Missing fields");
        return res.status(400).json({ success: false, message: 'Please provide both admin name and password' });
    }

    const query = 'SELECT * FROM admins WHERE admin_name = ?';
    db.query(query, [admin_name], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ success: false, message: 'Database error' });
        }

        if (results.length > 0) {
            const storedPassword = results[0].admin_password;

            if (admin_password === storedPassword) {
                console.log("Login successful");
                res.json({ success: true, redirectUrl: '/Admin Interface/admin.html' });
            } else {
                console.log("Invalid login credentials");
                res.status(401).json({ success: false, message: 'Invalid login credentials' });
            }
        } else {
            console.log("Admin not found");
            res.status(401).json({ success: false, message: 'Admin not found' });
        }
    });
});

// ... (previous imports and middleware remain the same)

// First, create the posts table if it doesn't exist
db.connect((err) => {
    if (err) {
        console.error('Could not connect to the database:', err);
        return;
    }
    console.log('Connected to the database');
    
    // Create posts table if it doesn't exist
    const createTableQuery = `
        CREATE TABLE IF NOT EXISTS posts (
            post_id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            category VARCHAR(100) NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES belly(user_id)
        )
    `;
    
    db.query(createTableQuery, (err) => {
        if (err) {
            console.error('Error creating posts table:', err);
            return;
        }
        console.log('Posts table ready');
    });
});

// Updated create-post route to include user information
app.post('/create-post', (req, res) => {
    // Check if user is logged in
    if (!req.session.user) {
        return res.status(401).json({ 
            success: false, 
            message: 'You must be logged in to create a post' 
        });
    }

    const { category, content } = req.body;
    const userId = req.session.user.userId;

    if (!category || !content) {
        return res.status(400).json({ 
            success: false, 
            message: 'Category and content are required' 
        });
    }

    // Insert the post data into the database with user_id
    const query = 'INSERT INTO posts (user_id, category, content) VALUES (?, ?, ?)';
    db.query(query, [userId, category, content], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ 
                success: false, 
                message: 'Database error',
                error: err.message 
            });
        }

        res.json({ 
            success: true, 
            message: 'Post created successfully',
            postId: results.insertId 
        });
    });
});


// Route to fetch posts for the logged-in user
app.get('/get-posts', (req, res) => {
    const userId = req.session.user ? req.session.user.userId : null; // Get user ID from session if logged in

    if (userId) {
        // Fetch posts for the logged-in user by their userId from the database
        const query = `
            SELECT 
                p.user_id,
                p.Content as content,
                p.CreatedAt as createdAt,
                p.category,
                b.username
            FROM posts p
            JOIN belly b ON p.user_id = b.user_id
            WHERE p.user_id = ?
            ORDER BY p.CreatedAt DESC
        `;
        
        db.query(query, [userId], (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ success: false, message: 'Error fetching posts' });
            }

            if (results.length > 0) {
                // Transform the dates to ensure proper formatting
                const formattedPosts = results.map(post => ({
                    ...post,
                    createdAt: new Date(post.createdAt).toISOString()
                }));
                res.json({ success: true, posts: formattedPosts });
            } else {
                res.json({ success: true, posts: [] });
            }
        });
    } else {
        res.status(401).json({ success: false, message: 'User not authenticated' });
    }
});

// Admin Endpoint to get all contacts from the 'belly' table
app.get('/api/get-all-contacts', (req, res) => {
    const query = 'SELECT * FROM belly';
    db.query(query, (err, result) => {
        if (err) {
            return res.status(500).send('Error fetching data');
        }
        res.json({ users: result });
    });
});

// Optional: Endpoint for filtering users
app.get('/api/filter-users', (req, res) => {
    const { search, userType, registrationDate } = req.query;
    let query = 'SELECT * FROM belly WHERE 1=1';

    if (search) {
        query += ` AND (name LIKE '%${search}%' OR email LIKE '%${search}%')`;
    }
    if (userType) {
        query += ` AND user_type = '${userType}'`;
    }
    if (registrationDate) {
        query += ` AND registration_date = '${registrationDate}'`;
    }

    db.query(query, (err, result) => {
        if (err) {
            return res.status(500).send('Error fetching data');
        }
        res.json({ users: result });
    });
});

// Route for updating user data
app.post('/update-user', (req, res) => {
    const { user_id, username } = req.body;

    // SQL query to update user in the database (assuming MySQL)
    const query = 'UPDATE belly SET username = ? WHERE user_id = ?';  // Updated column name

    db.query(query, [username, user_id], (err, result) => {
        if (err) {
            console.error("Error updating user:", err);
            return res.status(500).json({ success: false });
        }
        res.json({ success: true });
    });
});

// Route for deleting user
app.delete('/delete-user', (req, res) => {
    const { user_id } = req.body;

    // SQL query to delete user from the database (assuming MySQL)
    const query = 'DELETE FROM belly WHERE user_id = ?';  // Updated column name

    db.query(query, [user_id], (err, result) => {
        if (err) {
            console.error("Error deleting user:", err);
            return res.status(500).json({ success: false });
        }
        res.json({ success: true });
    });
});

// Route to fetch posts data
app.get('/api/posts', (req, res) => {
    const query = 'SELECT user_id, category, Content FROM posts'; // Added 'content'
    db.query(query, (err, results) => {
        if (err) throw err;
        res.json(results); // Send results to the frontend
    });
});

// Endpoint to fetch posts from the database
app.get('/api/posts', (req, res) => {
    const query = `
      SELECT posts.content, posts.category, posts.user_id
      FROM posts
      ORDER BY posts.created_at DESC
    `;
  
    db.query(query, (err, results) => {
      if (err) throw err;
      res.json(results); // Send the posts with the user_id to the frontend
    });
  });

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});




