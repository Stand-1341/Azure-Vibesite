require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken'); // Added jsonwebtoken
const bcrypt = require('bcrypt'); // Import bcrypt
const multer = require('multer');
const { BlobServiceClient } = require('@azure/storage-blob');
const sql = require('mssql'); // Import mssql
const fs = require('fs/promises');
const path = require('path');

const upload = multer({ storage: multer.memoryStorage() });
const blobServiceClient = BlobServiceClient.fromConnectionString(process.env.AZURE_STORAGE_CONNECTION_STRING);
const imageContainerName = process.env.AZURE_IMAGE_CONTAINER || 'post-images';

// Ensure image container exists at startup
(async () => {
  try {
    const containerClient = blobServiceClient.getContainerClient(imageContainerName);
    await containerClient.createIfNotExists({ access: 'blob' });
    console.log(`Blob container '${imageContainerName}' is ready.`);
  } catch (error) {
    console.error(`Error ensuring blob container '${imageContainerName}' exists:`, error);
    // Consider exiting if blob storage is essential: process.exit(1);
  }
})();

const app = express();
const port = process.env.PORT || 5000;

// --- Combined Database Configuration ---
const dbConfig = {
    server: process.env.DB_SERVER,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE, // Use the single database variable
    port: parseInt(process.env.DB_PORT || '1433'),
    pool: {
        max: 10, // Adjust pool size as needed
        min: 0,
        idleTimeoutMillis: 30000
    },
    options: {
        encrypt: process.env.DB_ENCRYPT === 'true',
        // Ensure trustServerCertificate matches Azure SQL requirements (usually false)
        trustServerCertificate: process.env.DB_TRUST_SERVER_CERTIFICATE === 'false'
    }
};

let pool; // Single pool for the combined database

async function applySchema() {
    try {
        const schemaPath = path.join(__dirname, 'combined_schema.sql');
        const schemaSql = await fs.readFile(schemaPath, 'utf8');

        const batches = schemaSql
            .split(/^\s*GO\s*$/gim)
            .map((batch) => batch.trim())
            .filter(Boolean);

        for (const batch of batches) {
            await pool.request().query(batch);
        }

        console.log(`Database schema ensured from ${schemaPath}`);
    } catch (err) {
        console.error('Failed to apply database schema:', err);
        throw err;
    }
}


// --- Updated Database Connection Function ---
async function connectDb() { // Renamed for clarity
    try {
        pool = await sql.connect(dbConfig);
        console.log('Database connection successful (MSSQL)');
        // Schema creation/validation should be handled externally via combined_schema.sql
    } catch (err) {
        console.error('Database connection failed (MSSQL): ', err);
        if (err.code === 'ELOGIN') {
            console.error('Login failed. Check database credentials and server details in .env');
        } else if (err.code === 'ENOTFOUND' || err.code === 'ETIMEOUT') {
            console.error('Connection failed. Check database server address/name and network connectivity.');
        }
        process.exit(1); // Exit if DB connection fails
    }
}

// --- Middleware ---

// CORS Configuration - BEFORE other routes
// Use the specific frontend URL from Blob Storage and localhost for development
const allowedOrigins = [
  process.env.FRONTEND_URL || 'https://siteacc.z5.web.core.windows.net', // Replace if your blob URL is different
  'http://localhost:3000' // For local dev
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
  credentials: true
}));

// Handle OPTIONS preflight requests
app.options('*', cors());

app.use(express.json());
// app.use(session({...})); // Removed session middleware usage

// --- NEW JWT Authentication Middleware ---

// Middleware to verify JWT token from Authorization header
const requireLogin = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized: No token provided.' });
    }

    try {
        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Token is valid, fetch user details (excluding password) to attach to request
        // This ensures user still exists and gets fresh role info
        const request = pool.request();
        request.input('userId', sql.Int, decoded.id); // Assuming JWT payload has user ID as 'id'
        // Select necessary user fields, EXCLUDING the plain text password
        const result = await request.query('SELECT id, username, email, role FROM Users WHERE id = @userId');

        if (result.recordset.length === 0) {
            // Should not happen if token was valid unless user was deleted after token issuance
            return res.status(401).json({ message: 'Unauthorized: User not found.' });
        }

        // Attach user info (without password) to the request object
        req.user = result.recordset[0];
        next(); // Proceed to the next middleware or route handler
    } catch (err) {
        if (err instanceof jwt.TokenExpiredError) {
            return res.status(401).json({ message: 'Unauthorized: Token expired.' });
        } else if (err instanceof jwt.JsonWebTokenError) {
            return res.status(401).json({ message: 'Unauthorized: Invalid token.' });
        }
        console.error('Authentication middleware error:', err);
        res.status(500).json({ message: 'Internal server error during authentication.' });
    }
};

// Middleware to check if user is admin (runs AFTER requireLogin)
const requireAdmin = (req, res, next) => {
    // req.user should be populated by requireLogin middleware
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Forbidden: Administrator privileges required.' });
    }
    next();
};

// --- API Routes ---

// Auth Routes
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ message: 'Username, email, and password are required.' });
    }
    // Basic password length check (consider more robust validation)
    if (password.length < 6) {
         return res.status(400).json({ message: 'Password must be at least 6 characters long.' });
    }

    try {
        // Check if username or email already exists
        const checkRequest = pool.request();
        checkRequest.input('username', sql.NVarChar, username);
        checkRequest.input('email', sql.NVarChar, email);
        const existingUser = await checkRequest.query('SELECT id FROM Users WHERE username = @username OR email = @email');

        if (existingUser.recordset.length > 0) {
            return res.status(409).json({ message: 'Username or email already exists.' });
        }

        // Hash the password
        const saltRounds = 10; // Standard recommendation
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Insert new user with hashed password
        const insertRequest = pool.request();
        insertRequest.input('username', sql.NVarChar, username);
        insertRequest.input('email', sql.NVarChar, email);
        insertRequest.input('hashedPassword', sql.NVarChar, hashedPassword); // Store hashed password
        const result = await insertRequest.query(
            'INSERT INTO Users (username, email, password_hash, role) OUTPUT INSERTED.id, INSERTED.username, INSERTED.email, INSERTED.role VALUES (@username, @email, @hashedPassword, DEFAULT)' // Explicitly add 'role' column
        );

        const newUser = result.recordset[0]; // Contains id, username, email, role
        console.log('User registered:', newUser);
        // Return the new user object (excluding password) on successful registration
        res.status(201).json({ message: 'User registered successfully.', user: { id: newUser.id, username: newUser.username, email: newUser.email, role: newUser.role } });

    } catch (err) {
        console.error('Registration error:', err);
        console.error('Error Code:', err.code);
        console.error('Error Number:', err.number);
        console.error('Error Stack:', err.stack);
        res.status(500).json({ message: 'Internal server error during registration.' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    try {
        // Find user by username
        const request = pool.request();
        request.input('username', sql.NVarChar, username);
        // Fetch the hashed password along with other details
        const result = await request.query('SELECT id, username, email, password_hash, role FROM Users WHERE username = @username');

        if (result.recordset.length === 0) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const user = result.recordset[0];

        // Compare the submitted password with the hashed password
        const passwordMatch = await bcrypt.compare(password, user.password_hash);

        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid credentials.' }); // Generic message for security
        }

        // Generate JWT Token
        const payload = {
            id: user.id,
            username: user.username,
            role: user.role
            // Add other non-sensitive info if needed
        };
        const secret = process.env.JWT_SECRET;
        const options = {
            expiresIn: process.env.JWT_EXPIRES_IN || '1h' // Use expiration from .env or default
        };

        if (!secret) {
            console.error("FATAL ERROR: JWT_SECRET is not defined in .env");
            return res.status(500).json({ message: 'Internal server error: JWT configuration missing.'});
        }

        const token = jwt.sign(payload, secret, options);

        console.log('User logged in:', { id: user.id, username: user.username, role: user.role });

        // Return the JWT token to the client
        res.json({
            message: 'Login successful.',
            token: token,
            // Optionally return user info again (without password)
            user: { id: user.id, username: user.username, email: user.email, role: user.role }
        });

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ message: 'Internal server error during login.' });
    }
});

// Logout is now primarily a frontend concern (clearing stored JWT)
app.post('/api/logout', (req, res) => {
    // Server-side logout for JWT is typically about managing token blocklists if needed,
    // but for simple cases, it's often just a client-side action.
    console.log('Logout endpoint hit (client should clear JWT).');
    res.json({ message: 'Logout successful (client-side responsibility).' });
});

// Get current user info based on JWT token
// Endpoint renamed to /api/me for clarity
app.get('/api/me', requireLogin, (req, res) => {
    // requireLogin middleware already verified the token and attached user info to req.user
    // Send back the user info (which excludes the password)
    res.json({ user: req.user });
});

// Update Password (uses requireLogin which validates JWT)
app.put('/api/update-password', requireLogin, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const userId = req.user.id; // Get user ID from middleware (attached after JWT verification)

    if (!oldPassword || !newPassword) {
        return res.status(400).json({ message: 'Old and new passwords are required.' });
    }
    if (newPassword.length < 6) {
        return res.status(400).json({ message: 'New password must be at least 6 characters long.' });
    }
    if (oldPassword === newPassword) {
        return res.status(400).json({ message: 'New password cannot be the same as the old password.' });
    }

    try {
        // Get current hashed password to verify oldPassword
        const request = pool.request();
        request.input('userId', sql.Int, userId);
        // Fetch the current hashed password
        const result = await request.query('SELECT password_hash FROM Users WHERE id = @userId');

        if (result.recordset.length === 0) {
            // Should not happen if requireLogin worked
            return res.status(404).json({ message: 'User not found.' });
        }
        const currentHashedPassword = result.recordset[0].password_hash;

        // Compare old password (hashed comparison)
        const match = await bcrypt.compare(oldPassword, currentHashedPassword);

        if (!match) {
            return res.status(401).json({ message: 'Incorrect old password.' });
        }

        // Hash the new password
        const saltRounds = 10; // Standard recommendation
        const newHashedPassword = await bcrypt.hash(newPassword, saltRounds);

        // Update password with the new hashed password
        const updateRequest = pool.request();
        updateRequest.input('userId', sql.Int, userId);
        updateRequest.input('newHashedPassword', sql.NVarChar, newHashedPassword);
        // Also update the 'updated_at' timestamp
        await updateRequest.query('UPDATE Users SET password_hash = @newHashedPassword, updated_at = GETDATE() WHERE id = @userId');

        console.log('Password updated for user ID:', userId);
        res.json({ message: 'Password updated successfully.' });

    } catch (err) {
        console.error('Password update error:', err);
        res.status(500).json({ message: 'Internal server error during password update.' });
    }
});

// --- Image Upload Endpoint (Posts Only) ---
app.post('/api/upload-image', requireLogin, upload.single('image'), async (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'No image file provided.' });
  try {
    const blobName = `${Date.now()}-${req.file.originalname.replace(/[^a-zA-Z0-9.]/g, '_')}`;
    const containerClient = blobServiceClient.getContainerClient(imageContainerName);
    const blockBlobClient = containerClient.getBlockBlobClient(blobName);
    await blockBlobClient.uploadData(req.file.buffer, {
        blobHTTPHeaders: { blobContentType: req.file.mimetype }
    });
    console.log(`Image uploaded successfully: ${blockBlobClient.url}`);
    res.json({ imageUrl: blockBlobClient.url });
  } catch (err) {
    console.error('Image upload error:', err);
    res.status(500).json({ message: 'Image upload failed due to server error.' });
  }
});

// --- Discussion Board Routes (Now using single 'pool' and requireLogin JWT middleware) ---

// Get all posts (public)
app.get('/api/posts', async (req, res) => {
    const communityFilter = req.query.community; // Get community from query params

    try {
        const request = pool.request(); // Create a new request object for mssql

        // Corrected query using separate Comments and Replies tables
        let query = `
            SELECT
                p.id, p.title, p.content, p.created_at, p.image_url, p.community, -- Include community
                u.username AS author_username, u.id AS user_id,
                COALESCE(c.comment_count, 0) AS comment_count, -- Count of direct comments
                COALESCE(r.reply_count, 0) AS reply_count      -- Count of replies via comments
            FROM posts p
            JOIN users u ON p.user_id = u.id
            LEFT JOIN (
                -- Subquery to count direct comments per post
                SELECT post_id, COUNT(*) AS comment_count
                FROM Comments
                GROUP BY post_id
            ) c ON p.id = c.post_id
            LEFT JOIN (
                -- Subquery to count replies associated with comments of a post
                SELECT Comments.post_id, COUNT(Replies.id) AS reply_count
                FROM Comments
                JOIN Replies ON Comments.id = Replies.comment_id
                GROUP BY Comments.post_id
            ) r ON p.id = r.post_id
        `;

        // Use named parameters for mssql
        if (communityFilter) {
            query += ` WHERE p.community = @communityFilter`;
            // Make sure to decode URI component if the community name might contain special characters
            request.input('communityFilter', sql.VarChar(50), decodeURIComponent(communityFilter));
        } else {
            // No community filter applied if parameter is not present
        }

        query += ` ORDER BY p.created_at DESC`;

        const result = await request.query(query); // Execute using the request object with parameters

        // Ensure counts are numbers and handle potential nulls from LEFT JOIN
        const posts = result.recordset.map(post => ({
            ...post,
            comment_count: Number(post.comment_count || 0), // Add fallback to 0
            reply_count: Number(post.reply_count || 0)   // Add fallback to 0
        }));

        res.json(posts);
    } catch (err) {
        console.error('Error fetching posts:', err.message); // Log the error message
        // Consider logging the full error object in development for more details: console.error(err);
        res.status(500).json({ message: 'Server error fetching posts', error: err.message }); // Send error details back in response
    }
});

// Get a single post by ID
app.get('/api/posts/:id', async (req, res) => {
    const postId = parseInt(req.params.id);
    if (isNaN(postId)) {
        return res.status(400).json({ message: 'Invalid post ID' });
    }

    try {
        const query = `
            SELECT p.id, p.title, p.content, p.created_at, p.image_url, p.community, -- Include community
                   u.username AS author_username, u.id AS user_id
            FROM posts p
            JOIN users u ON p.user_id = u.id
            WHERE p.id = @postId;
        `;
        const request = pool.request();
        request.input('postId', sql.Int, postId);
        const { recordset } = await request.query(query);

        if (recordset.length === 0) {
            return res.status(404).json({ message: 'Post not found' });
        }

        res.json(recordset[0]);
    } catch (error) {
        console.error('Failed to fetch post:', error);
        res.status(500).json({ message: 'Failed to fetch post' });
    }
});

// POST a new post (requires login via JWT)
app.post('/api/posts', requireLogin, async (req, res) => { // Added requireLogin middleware
    const { title, content, imageUrl, community } = req.body; // Destructure community
    const userId = req.user.id; // Get user ID from verified JWT payload (via requireLogin)

    // Basic validation
    if (!title || !content || !community) { // Add community check
        return res.status(400).json({ message: 'Title, content, and community are required' });
    }

    // Optional: Add more specific validation for the community format if needed
    if (typeof community !== 'string' || community.length > 50) {
        return res.status(400).json({ message: 'Invalid community format' });
    }

    try {
        const query = `
            INSERT INTO posts (user_id, title, content, image_url, community)
            OUTPUT INSERTED.id, INSERTED.title, INSERTED.content, INSERTED.created_at, INSERTED.image_url, INSERTED.community
            VALUES (@userId, @title, @content, @imageUrl, @community);
        `;
        const request = pool.request();
        request.input('userId', sql.Int, userId);
        request.input('title', sql.NVarChar, title);
        request.input('content', sql.NVarChar, content);
        request.input('imageUrl', sql.NVarChar, imageUrl);
        request.input('community', sql.NVarChar, community);
        const { recordset } = await request.query(query);
        
        // Fetch the author's username to include in the response
        const authorQuery = 'SELECT username FROM users WHERE id = @userId';
        const authorRequest = pool.request();
        authorRequest.input('userId', sql.Int, userId);
        const authorResult = await authorRequest.query(authorQuery);
        const authorUsername = authorResult.recordset[0]?.username || 'Unknown';

        const newPost = {
            ...recordset[0],
            author_username: authorUsername,
            user_id: userId,
            comment_count: 0, // New posts have 0 comments
            reply_count: 0    // New posts have 0 replies
        };

        res.status(201).json(newPost);
    } catch (error) {
        console.error('Failed to create post:', error);
        res.status(500).json({ message: 'Failed to create post' });
    }
});

// PUT/UPDATE a post (requires login via JWT, user must be author or admin)
app.put('/api/posts/:postId', requireLogin, async (req, res) => { // Added requireLogin middleware
    const { title, content } = req.body;
    const postId = parseInt(req.params.postId);
    const userId = req.user.id; // From JWT
    const userRole = req.user.role; // From JWT

    if (isNaN(postId)) {
        return res.status(400).json({ message: 'Invalid post ID.' });
    }
    if (!title || !content) {
        return res.status(400).json({ message: 'Title and content are required.' });
    }

    try {
        // First, check if the post exists and get the author's ID
        const checkRequest = pool.request();
        checkRequest.input('postId', sql.Int, postId);
        const postResult = await checkRequest.query('SELECT user_id FROM Posts WHERE id = @postId');

        if (postResult.recordset.length === 0) {
            return res.status(404).json({ message: 'Post not found.' });
        }

        const postAuthorId = postResult.recordset[0].user_id;

        // Check if the logged-in user is the author OR an admin
        if (postAuthorId !== userId && userRole !== 'admin') {
            return res.status(403).json({ message: 'Forbidden: You can only edit your own posts.' });
        }

        // Proceed with the update
        const updateRequest = pool.request();
        updateRequest.input('postId', sql.Int, postId);
        updateRequest.input('title', sql.NVarChar, title);
        updateRequest.input('content', sql.NVarChar, content);
        // Update timestamp if your schema has an updated_at for posts
        // updateRequest.input('userId', sql.Int, userId); // Might not need userId here unless logging who updated

        const result = await updateRequest.query(
            'UPDATE Posts SET title = @title, content = @content WHERE id = @postId; SELECT @@ROWCOUNT as rowsAffected;'
        );

        if (result.recordset[0].rowsAffected > 0) {
             // Optionally fetch and return the updated post
             const fetchRequest = pool.request();
             fetchRequest.input('postId', sql.Int, postId);
             const updatedPost = await fetchRequest.query(`
                SELECT p.*, u.username
                FROM Posts p
                JOIN Users u ON p.user_id = u.id
                WHERE p.id = @postId
             `);
             if (updatedPost.recordset.length > 0) {
                 res.json(updatedPost.recordset[0]);
             } else {
                 // Should not happen if update succeeded
                 res.status(404).json({ message: 'Post not found after update.' });
             }
        } else {
            // Should not happen if check above passed, but good practice
            res.status(404).json({ message: 'Post not found or no changes made.' });
        }
    } catch (err) {
        console.error('Error updating post:', err);
        res.status(500).json({ message: 'Internal server error while updating post.' });
    }
});

// DELETE a post (requires login via JWT, user must be author or admin)
app.delete('/api/posts/:postId', requireLogin, async (req, res) => { // Added requireLogin middleware
    const postId = parseInt(req.params.postId);
    const userId = req.user.id; // From JWT
    const userRole = req.user.role; // From JWT

    if (isNaN(postId)) {
        return res.status(400).json({ message: 'Invalid post ID.' });
    }

    try {
        // Check if post exists and get author ID
        const checkRequest = pool.request();
        checkRequest.input('postId', sql.Int, postId);
        const postResult = await checkRequest.query('SELECT user_id FROM Posts WHERE id = @postId');

        if (postResult.recordset.length === 0) {
            return res.status(404).json({ message: 'Post not found.' });
        }

        const postAuthorId = postResult.recordset[0].user_id;

        // Authorization check
        if (postAuthorId !== userId && userRole !== 'admin') {
            return res.status(403).json({ message: 'Forbidden: You can only delete your own posts.' });
        }

        // Proceed with deletion
        const deleteRequest = pool.request();
        deleteRequest.input('postId', sql.Int, postId);
        const result = await deleteRequest.query('DELETE FROM Posts WHERE id = @postId; SELECT @@ROWCOUNT as rowsAffected;'); // Cascade should delete comments/replies based on schema FKs

        if (result.recordset[0].rowsAffected > 0) {
            res.status(200).json({ message: 'Post deleted successfully.' }); // Use 200 OK for successful delete
        } else {
            res.status(404).json({ message: 'Post not found or already deleted.' });
        }
    } catch (err) {
        console.error('Error deleting post:', err);
        res.status(500).json({ message: 'Internal server error while deleting post.' });
    }
});

// DELETE endpoint for deleting a post
app.delete('/api/posts/:id', requireLogin, async (req, res) => {
    const postId = parseInt(req.params.id, 10);
    const userId = req.user.id;
    const connection = await sql.connect(dbConfig);
    const transaction = new sql.Transaction(connection);

    try {
        await transaction.begin();
        const postRequest = new sql.Request(transaction);

        // 1. Find the post and verify ownership & get image URL
        const postResult = await postRequest.query`SELECT user_id, image_url FROM Posts WHERE id = ${postId}`;

        if (postResult.recordset.length === 0) {
            await transaction.rollback();
            return res.status(404).send('Post not found.');
        }

        const post = postResult.recordset[0];
        if (post.user_id !== userId) {
            await transaction.rollback();
            return res.status(403).send('You are not authorized to delete this post.');
        }

        // 2. Delete associated image from Azure Blob Storage if it exists
        if (post.image_url) {
            try {
                const containerClient = blobServiceClient.getContainerClient(imageContainerName);
                // Extract blob name from URL (assuming URL format is consistent)
                const urlParts = post.image_url.split('/');
                const blobName = urlParts[urlParts.length - 1];
                if (blobName) {
                    const blockBlobClient = containerClient.getBlockBlobClient(blobName);
                    await blockBlobClient.deleteIfExists();
                    console.log(`Deleted blob ${blobName} for post ${postId}`);
                }
            } catch (blobError) {
                console.error(`Failed to delete blob for post ${postId}:`, blobError);
                // Decide if you want to stop the deletion or just log the error
                // Rolling back for safety
                await transaction.rollback();
                return res.status(500).send('Failed to delete associated image.');
            }
        }

        // 3. Delete associated replies (depend on comments)
        const replyRequest = new sql.Request(transaction);
        await replyRequest.query`
            DELETE FROM Replies
            WHERE comment_id IN (SELECT id FROM Comments WHERE post_id = ${postId})
        `;

        // 4. Delete associated comments (depend on posts)
        const commentRequest = new sql.Request(transaction);
        await commentRequest.query`DELETE FROM Comments WHERE post_id = ${postId}`;

        // 5. Delete the post itself
        const deletePostRequest = new sql.Request(transaction);
        const result = await deletePostRequest.query`DELETE FROM Posts WHERE id = ${postId}`;

        if (result.rowsAffected[0] === 0) {
            // This case should ideally not happen if the initial check passed, but good for safety
            await transaction.rollback();
            return res.status(404).send('Post not found during deletion.');
        }

        await transaction.commit();
        res.status(200).send({ message: 'Post deleted successfully.' }); // Use 200 OK with message instead of 204

    } catch (err) {
        console.error('Error deleting post:', err);
        if (transaction.rolledBack === false) {
             await transaction.rollback();
        }
        res.status(500).send('Failed to delete post.');
    } finally {
        if (connection) {
            await connection.close();
        }
    }
});

// --- Comment Routes (Now using requireLogin JWT middleware where needed) ---

// GET comments for a post (public)
app.get('/api/posts/:postId/comments', async (req, res) => {
    const postId = parseInt(req.params.postId);
    if (isNaN(postId)) {
        return res.status(400).json({ message: 'Invalid post ID.' });
    }

    try {
        const commentsRequest = pool.request();
        commentsRequest.input('postId', sql.Int, postId);
        const commentsResult = await commentsRequest.query(`
            SELECT c.id, c.post_id, c.user_id, c.comment_text, c.created_at, u.username as author_username
            FROM Comments c
            JOIN Users u ON c.user_id = u.id
            WHERE c.post_id = @postId
            ORDER BY c.created_at ASC
        `);
        res.json(commentsResult.recordset);
    } catch (err) {
        console.error('Error fetching comments:', err);
        res.status(500).json({ message: 'Error fetching comments.' });
    }
});

// POST a comment on a post (requires login via JWT)
app.post('/api/posts/:postId/comments', requireLogin, async (req, res) => { // Added requireLogin
    const postId = parseInt(req.params.postId);
    const { content } = req.body;
    const userId = req.user.id; // From JWT

    if (isNaN(postId)) {
        return res.status(400).json({ message: 'Invalid post ID.' });
    }
    if (!content) {
        return res.status(400).json({ message: 'Comment content is required.' });
    }

    try {
        // Optional: Check if post exists before allowing comment
        const postCheck = pool.request();
        postCheck.input('postId', sql.Int, postId);
        const postExists = await postCheck.query('SELECT 1 FROM Posts WHERE id = @postId');
        if (postExists.recordset.length === 0) {
             return res.status(404).json({ message: 'Post not found.' });
        }

        const request = pool.request();
        request.input('postId', sql.Int, postId);
        request.input('userId', sql.Int, userId);
        request.input('content', sql.NVarChar, content);
        const result = await request.query(
            'INSERT INTO Comments (post_id, user_id, comment_text) OUTPUT INSERTED.* VALUES (@postId, @userId, @content)'
        );
        // Fetch the username to return with the comment
        const newComment = result.recordset[0];
        const userRequest = pool.request();
        userRequest.input('userId', sql.Int, newComment.user_id);
        const userResult = await userRequest.query('SELECT username FROM Users WHERE id = @userId');
        newComment.username = userResult.recordset[0]?.username || 'Unknown User';

        res.status(201).json(newComment);
    } catch (err) {
        console.error('Error creating comment:', err);
        res.status(500).json({ message: 'Internal server error while creating comment.' });
    }
});

// PUT/UPDATE a comment (requires login via JWT, user must be author or admin)
app.put('/api/comments/:commentId', requireLogin, async (req, res) => { // Added requireLogin
    const commentId = parseInt(req.params.commentId);
    const { content } = req.body;
    const userId = req.user.id; // From JWT
    const userRole = req.user.role; // From JWT

    if (isNaN(commentId)) {
        return res.status(400).json({ message: 'Invalid comment ID.' });
    }
    if (!content) {
        return res.status(400).json({ message: 'Comment content is required.' });
    }

    try {
        // Check if comment exists and get author ID
        const checkRequest = pool.request();
        checkRequest.input('commentId', sql.Int, commentId);
        const commentResult = await checkRequest.query('SELECT user_id FROM Comments WHERE id = @commentId');

        if (commentResult.recordset.length === 0) {
            return res.status(404).json({ message: 'Comment not found.' });
        }

        const commentAuthorId = commentResult.recordset[0].user_id;

        // Authorization check
        if (commentAuthorId !== userId && userRole !== 'admin') {
            return res.status(403).json({ message: 'Forbidden: You can only edit your own comments.' });
        }

        // Proceed with update
        const updateRequest = pool.request();
        updateRequest.input('commentId', sql.Int, commentId);
        updateRequest.input('content', sql.NVarChar, content);
        // Update timestamp if your schema has an updated_at for comments
        const result = await updateRequest.query(
            'UPDATE Comments SET comment_text = @content WHERE id = @commentId; SELECT @@ROWCOUNT as rowsAffected;'
        );

        if (result.recordset[0].rowsAffected > 0) {
             // Optionally fetch and return the updated comment
            const fetchRequest = pool.request();
            fetchRequest.input('commentId', sql.Int, commentId);
            const updatedComment = await fetchRequest.query(`
                SELECT c.*, u.username
                FROM Comments c
                JOIN Users u ON c.user_id = u.id
                WHERE c.id = @commentId
            `);
            if (updatedComment.recordset.length > 0) {
                res.json(updatedComment.recordset[0]);
            } else {
                 res.status(404).json({ message: 'Comment not found after update.' });
            }
        } else {
            res.status(404).json({ message: 'Comment not found or no changes made.' });
        }
    } catch (err) {
        console.error('Error updating comment:', err);
        res.status(500).json({ message: 'Internal server error while updating comment.' });
    }
});

// DELETE a comment (requires login via JWT, user must be author or admin)
app.delete('/api/comments/:commentId', requireLogin, async (req, res) => { // Added requireLogin
    const commentId = parseInt(req.params.commentId);
    const userId = req.user.id; // From JWT
    const userRole = req.user.role; // From JWT

    if (isNaN(commentId)) {
        return res.status(400).json({ message: 'Invalid comment ID.' });
    }

    try {
        // Check if comment exists and get author ID
        const checkRequest = pool.request();
        checkRequest.input('commentId', sql.Int, commentId);
        const commentResult = await checkRequest.query('SELECT user_id FROM Comments WHERE id = @commentId');

        if (commentResult.recordset.length === 0) {
            return res.status(404).json({ message: 'Comment not found.' });
        }

        const commentAuthorId = commentResult.recordset[0].user_id;

        // Authorization check
        if (commentAuthorId !== userId && userRole !== 'admin') {
            return res.status(403).json({ message: 'Forbidden: You can only delete your own comments.' });
        }

        // Proceed with deletion
        const deleteRequest = pool.request();
        deleteRequest.input('commentId', sql.Int, commentId);
        const result = await deleteRequest.query('DELETE FROM Comments WHERE id = @commentId; SELECT @@ROWCOUNT as rowsAffected;'); // Cascade should delete replies

        if (result.recordset[0].rowsAffected > 0) {
            res.status(200).json({ message: 'Comment deleted successfully.' });
        } else {
            res.status(404).json({ message: 'Comment not found or already deleted.' });
        }
    } catch (err) {
        console.error('Error deleting comment:', err);
        res.status(500).json({ message: 'Internal server error while deleting comment.' });
    }
});

// --- Reply Routes (Similar JWT protection logic as Comments) ---

// GET replies for a comment (public)
app.get('/api/comments/:commentId/replies', async (req, res) => {
    const commentId = parseInt(req.params.commentId);
    if (isNaN(commentId)) {
        return res.status(400).json({ message: 'Invalid comment ID.' });
    }

    try {
        const repliesRequest = pool.request();
        repliesRequest.input('commentId', sql.Int, commentId);
        const repliesResult = await repliesRequest.query(`
            SELECT r.id, r.comment_id, r.user_id, r.reply_text, r.created_at, u.username as author_username
            FROM Replies r
            JOIN Users u ON r.user_id = u.id
            WHERE r.comment_id = @commentId
            ORDER BY r.created_at ASC
        `);
        res.json(repliesResult.recordset);
    } catch (err) {
        console.error('Error fetching replies:', err);
        res.status(500).json({ message: 'Error fetching replies.' });
    }
});

// POST a reply to a comment (requires login via JWT)
app.post('/api/comments/:commentId/replies', requireLogin, async (req, res) => { // Added requireLogin
    const commentId = parseInt(req.params.commentId);
    const { content } = req.body;
    const userId = req.user.id; // From JWT

    if (isNaN(commentId)) {
        return res.status(400).json({ message: 'Invalid comment ID.' });
    }
    if (!content) {
        return res.status(400).json({ message: 'Reply content is required.' });
    }

     try {
        // Optional: Check if comment exists
        const commentCheck = pool.request();
        commentCheck.input('commentId', sql.Int, commentId);
        const commentExists = await commentCheck.query('SELECT 1 FROM Comments WHERE id = @commentId');
        if (commentExists.recordset.length === 0) {
             return res.status(404).json({ message: 'Comment not found.' });
        }

        const request = pool.request();
        request.input('commentId', sql.Int, commentId);
        request.input('userId', sql.Int, userId);
        request.input('content', sql.NVarChar, content);
        const result = await request.query(
            'INSERT INTO Replies (comment_id, user_id, reply_text) OUTPUT INSERTED.* VALUES (@commentId, @userId, @content)'
        );
        // Fetch username to return with reply
        const newReply = result.recordset[0];
        const userRequest = pool.request();
        userRequest.input('userId', sql.Int, newReply.user_id);
        const userResult = await userRequest.query('SELECT username FROM Users WHERE id = @userId');
        newReply.username = userResult.recordset[0]?.username || 'Unknown User';

        res.status(201).json(newReply);
    } catch (err) {
        console.error('Error creating reply:', err);
        res.status(500).json({ message: 'Internal server error while creating reply.' });
    }
});

// PUT/UPDATE a reply (requires login via JWT, user must be author or admin)
app.put('/api/replies/:replyId', requireLogin, async (req, res) => { // Added requireLogin
    const replyId = parseInt(req.params.replyId);
    const { content } = req.body;
    const userId = req.user.id; // From JWT
    const userRole = req.user.role; // From JWT

    if (isNaN(replyId)) {
        return res.status(400).json({ message: 'Invalid reply ID.' });
    }
    if (!content) {
        return res.status(400).json({ message: 'Reply content is required.' });
    }

     try {
        // Check if reply exists and get author ID
        const checkRequest = pool.request();
        checkRequest.input('replyId', sql.Int, replyId);
        const replyResult = await checkRequest.query('SELECT user_id FROM Replies WHERE id = @replyId');

        if (replyResult.recordset.length === 0) {
            return res.status(404).json({ message: 'Reply not found.' });
        }

        const replyAuthorId = replyResult.recordset[0].user_id;

        // Authorization check
        if (replyAuthorId !== userId && userRole !== 'admin') {
            return res.status(403).json({ message: 'Forbidden: You can only edit your own replies.' });
        }

        // Proceed with update
        const updateRequest = pool.request();
        updateRequest.input('replyId', sql.Int, replyId);
        updateRequest.input('content', sql.NVarChar, content);
        const result = await updateRequest.query(
            'UPDATE Replies SET reply_text = @content WHERE id = @replyId; SELECT @@ROWCOUNT as rowsAffected;'
        );

        if (result.recordset[0].rowsAffected > 0) {
            // Optionally fetch and return the updated reply
            const fetchRequest = pool.request();
            fetchRequest.input('replyId', sql.Int, replyId);
            const updatedReply = await fetchRequest.query(`
                SELECT r.*, u.username
                FROM Replies r
                JOIN Users u ON r.user_id = u.id
                WHERE r.id = @replyId
            `);
             if (updatedReply.recordset.length > 0) {
                res.json(updatedReply.recordset[0]);
            } else {
                 res.status(404).json({ message: 'Reply not found after update.' });
            }
        } else {
            res.status(404).json({ message: 'Reply not found or no changes made.' });
        }
    } catch (err) {
        console.error('Error updating reply:', err);
        res.status(500).json({ message: 'Internal server error while updating reply.' });
    }
});

// DELETE a reply (requires login via JWT, user must be author or admin)
app.delete('/api/replies/:replyId', requireLogin, async (req, res) => { // Added requireLogin
    const replyId = parseInt(req.params.replyId);
    const userId = req.user.id; // From JWT
    const userRole = req.user.role; // From JWT

    if (isNaN(replyId)) {
        return res.status(400).json({ message: 'Invalid reply ID.' });
    }

     try {
        // Check if reply exists and get author ID
        const checkRequest = pool.request();
        checkRequest.input('replyId', sql.Int, replyId);
        const replyResult = await checkRequest.query('SELECT user_id FROM Replies WHERE id = @replyId');

        if (replyResult.recordset.length === 0) {
            return res.status(404).json({ message: 'Reply not found.' });
        }

        const replyAuthorId = replyResult.recordset[0].user_id;

        // Authorization check
        if (replyAuthorId !== userId && userRole !== 'admin') {
            return res.status(403).json({ message: 'Forbidden: You can only delete your own replies.' });
        }

        // Proceed with deletion
        const deleteRequest = pool.request();
        deleteRequest.input('replyId', sql.Int, replyId);
        const result = await deleteRequest.query('DELETE FROM Replies WHERE id = @replyId; SELECT @@ROWCOUNT as rowsAffected;');

        if (result.recordset[0].rowsAffected > 0) {
            res.status(200).json({ message: 'Reply deleted successfully.' });
        } else {
            res.status(404).json({ message: 'Reply not found or already deleted.' });
        }
    } catch (err) {
        console.error('Error deleting reply:', err);
        res.status(500).json({ message: 'Internal server error while deleting reply.' });
    }
});

// --- User Management Routes (Require Admin Role) ---

// GET all users (admin only)
app.get('/api/users', requireLogin, requireAdmin, async (req, res) => {
    try {
        const request = pool.request();
        // Select users but EXCLUDE the plain text password
        const result = await request.query('SELECT id, username, email, role, created_at, updated_at FROM Users ORDER BY username');
        res.json(result.recordset);
    } catch (err) {
        console.error('Error fetching users:', err);
        res.status(500).json({ message: 'Internal server error while fetching users.' });
    }
});

// GET a single user by ID (admin only)
app.get('/api/users/:userId', requireLogin, requireAdmin, async (req, res) => {
    const userId = parseInt(req.params.userId);
    if (isNaN(userId)) {
        return res.status(400).json({ message: 'Invalid user ID.' });
    }

    try {
        const request = pool.request();
        request.input('userId', sql.Int, userId);
        // Select user but EXCLUDE the plain text password
        const result = await request.query('SELECT id, username, email, role, created_at, updated_at FROM Users WHERE id = @userId');

        if (result.recordset.length === 0) {
            return res.status(404).json({ message: 'User not found.' });
        }
        res.json(result.recordset[0]);
    } catch (err) {
        console.error('Error fetching user:', err);
        res.status(500).json({ message: 'Internal server error while fetching user.' });
    }
});

// PUT/UPDATE a user's details (admin only)
app.put('/api/users/:userId', requireLogin, requireAdmin, async (req, res) => {
    const userId = parseInt(req.params.userId);
    const { username, email, role } = req.body; // Password cannot be changed here

    if (isNaN(userId)) {
        return res.status(400).json({ message: 'Invalid user ID.' });
    }
    if (!username || !email || !role) {
        return res.status(400).json({ message: 'Username, email, and role are required.' });
    }
     if (!['user', 'admin'].includes(role)) {
         return res.status(400).json({ message: 'Invalid role specified. Must be "user" or "admin".' });
     }
     // Prevent admin from accidentally locking themselves out of admin role if they are the only admin? (More complex logic)

    try {
         // Check for username/email conflicts with OTHER users
        const checkRequest = pool.request();
        checkRequest.input('userId', sql.Int, userId);
        checkRequest.input('username', sql.NVarChar, username);
        checkRequest.input('email', sql.NVarChar, email);
        const conflictCheck = await checkRequest.query(
            'SELECT id FROM Users WHERE (username = @username OR email = @email) AND id <> @userId'
        );

        if (conflictCheck.recordset.length > 0) {
            return res.status(409).json({ message: 'Username or email already exists for another user.' });
        }

        const request = pool.request();
        request.input('userId', sql.Int, userId);
        request.input('username', sql.NVarChar, username);
        request.input('email', sql.NVarChar, email);
        request.input('role', sql.VarChar, role); // Use correct type VarChar
        const result = await request.query(
            'UPDATE Users SET username = @username, email = @email, role = @role, updated_at = GETDATE() WHERE id = @userId; SELECT @@ROWCOUNT as rowsAffected;'
        );

        if (result.recordset[0].rowsAffected > 0) {
            // Fetch and return updated user data (excluding password)
            const fetchRequest = pool.request();
            fetchRequest.input('userId', sql.Int, userId);
            const updatedUser = await fetchRequest.query('SELECT id, username, email, role, created_at, updated_at FROM Users WHERE id = @userId');
            if (updatedUser.recordset.length > 0) {
                 res.json(updatedUser.recordset[0]);
            } else {
                 res.status(404).json({ message: 'User not found after update.' });
            }
        } else {
            res.status(404).json({ message: 'User not found.' });
        }
    } catch (err) {
        console.error('Error updating user:', err);
        res.status(500).json({ message: 'Internal server error while updating user.' });
    }
});

// DELETE a user (admin only)
app.delete('/api/users/:userId', requireLogin, requireAdmin, async (req, res) => {
    const userIdToDelete = parseInt(req.params.userId);
    const adminUserId = req.user.id; // ID of the admin performing the action

    if (isNaN(userIdToDelete)) {
        return res.status(400).json({ message: 'Invalid user ID.' });
    }

    // Prevent admin from deleting themselves
    if (userIdToDelete === adminUserId) {
        return res.status(400).json({ message: 'Admin cannot delete their own account.' });
    }

    try {
        const request = pool.request();
        request.input('userId', sql.Int, userIdToDelete);
        const result = await request.query('DELETE FROM Users WHERE id = @userId; SELECT @@ROWCOUNT as rowsAffected;'); // Cascade delete should handle posts/comments/replies

        if (result.recordset[0].rowsAffected > 0) {
            console.log(`Admin (ID: ${adminUserId}) deleted user (ID: ${userIdToDelete})`);
            res.status(200).json({ message: 'User deleted successfully.' });
        } else {
            res.status(404).json({ message: 'User not found.' });
        }
    } catch (err) {
        // Handle potential foreign key constraint issues if cascade delete isn't set up correctly
        if (err.number === 547) { // Foreign key violation error number in MSSQL
             console.error('Error deleting user due to foreign key constraints:', err);
             res.status(409).json({ message: 'Cannot delete user. They may still have associated posts, comments, or replies that need to be removed first.' });
        } else {
            console.error('Error deleting user:', err);
            res.status(500).json({ message: 'Internal server error while deleting user.' });
        }
    }
});

// --- Server Start ---
async function startServer() {
    await connectDb(); // Ensure DB is connected before starting listener
    await applySchema(); // Ensure DB schema exists/updated before handling requests
    app.listen(port, () => {
        console.log(`Server running on port ${port}`);
        if (!process.env.JWT_SECRET) {
             console.warn("WARNING: JWT_SECRET is not set in the .env file. Authentication will fail.");
        }
    });
}

startServer(); 