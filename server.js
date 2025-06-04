const express = require('express');
const crypto = require('crypto');
const setupDatabase = require('./database.js');
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const { body, validationResult } = require('express-validator');
const fs = require('fs');

const app = express();
const port = 3000; // We'll address environment variables later if desired
// ...existing code...

const parentAuth = require('express').Router();
// Middleware to parse JSON bodies
const multer = require('multer');
const path = require('path');
// Handle file uploads
app.get('/api/download/:fileId', async (req, res) => {
    const fileId = req.params.fileId;
    // Look up the original filename in the database
    const form = await db.get('SELECT originalFileName FROM forms WHERE filePath = ?', [fileId]);
    if (!form) return res.status(404).send('File not found');
    const filePath = path.join(__dirname, 'uploads', fileId);
    res.download(filePath, form.originalFileName);
});
const upload = multer({
    dest: 'uploads/',
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        if (['.pdf', '.doc', '.docx'].includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error('Only PDF, DOC, and DOCX files are allowed.'));
        }
    }
});


async function hashUploadedFile(filePath) {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash('sha256');
        const stream = fs.createReadStream(filePath);
        stream.on('data', data => hash.update(data));
        stream.on('end', () => resolve(hash.digest('hex')));
        stream.on('error', reject);
    });
}

// Parent Registration
parentAuth.post('/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });
    try {
        const hashed = await bcrypt.hash(password, 10);
        await db.run('INSERT INTO parents (email, password) VALUES (?, ?)', [email.toLowerCase(), hashed]);
        res.status(201).json({ message: 'Registration successful.' });
    } catch (err) {
        if (err.message.includes('UNIQUE')) {
            res.status(409).json({ error: 'Email already registered.' });
        } else {
            res.status(500).json({ error: 'Registration failed.' });
        }
    }
});

// Parent Login
parentAuth.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const parent = await db.get('SELECT * FROM parents WHERE email = ?', [email.toLowerCase()]);
    if (!parent) return res.status(401).json({ error: 'Invalid credentials.' });
    const match = await bcrypt.compare(password, parent.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials.' });
    req.session.parent = { id: parent.id, email: parent.email };
    res.json({ message: 'Login successful.' });
});

// Parent Forgot Password (send reset link - simulation)
parentAuth.post('/forgot', async (req, res) => {
    const { email } = req.body;
    const parent = await db.get('SELECT * FROM parents WHERE email = ?', [email.toLowerCase()]);
    if (!parent) return res.status(200).json({ message: 'If registered, a reset link will be sent.' });
    // In production, generate a token and email it. Here, just simulate:
    res.json({ message: 'Password reset link sent (simulated).' });
});

// Parent Reset Password (simulate with direct reset)
parentAuth.post('/reset', async (req, res) => {
    const { email, newPassword } = req.body;
    if (!email || !newPassword) return res.status(400).json({ error: 'Email and new password required.' });
    const hashed = await bcrypt.hash(newPassword, 10);
    const result = await db.run('UPDATE parents SET password = ? WHERE email = ?', [hashed, email.toLowerCase()]);
    if (result.changes === 0) return res.status(404).json({ error: 'Parent not found.' });
    res.json({ message: 'Password reset successful.' });
});
app.use(express.json({ limit: '10mb' })); // For signature image data
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Session Middleware
app.use(
  session({
    store: new SQLiteStore({
      db: 'sessions.db', // Separate file for session data
      dir: './', 
      table: 'sessions' // Explicitly name the sessions table
    }),
    secret: 'REPLACE_THIS_WITH_A_LONG_RANDOM_SECRET_STRING_LATER', // IMPORTANT!
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 1 week
  })
);
app.use('/api/parent', parentAuth);

// Middleware to check if admin is authenticated
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized: You must be logged in.' });
    }
}

let db; // Will be initialized in startServer

// Helper: Create Document Hash (essential for digital signature)
function createDocumentHash(form) {
    if (!form || !form.id || !form.title || !form.description || !form.studentName || !form.parentEmail) {
        console.error("Missing data for hashing:", form);
        return null; // Or throw an error
    }
    const dataString = `${form.id}|${form.title}|${form.description}|${form.studentName}|${form.parentEmail}`;
    return crypto.createHash('sha256').update(dataString).digest('hex');
}

// Helper: Get or Generate Parent RSA Keys
async function getOrGenerateParentRsaKeys(parentEmail) {
    let keys = await db.get('SELECT public_key, private_key FROM parent_rsa_keys WHERE parent_email = ?', [parentEmail]);
    if (keys) {
        return { publicKey: keys.public_key, privateKey: keys.private_key };
    } else {
        console.log(`Generating new RSA key pair for ${parentEmail}`);
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        try {
            await db.run('INSERT INTO parent_rsa_keys (parent_email, public_key, private_key) VALUES (?, ?, ?)', [parentEmail, publicKey, privateKey]);
            return { publicKey, privateKey };
        } catch (error) {
            console.error(`Failed to store RSA keys for ${parentEmail}:`, error);
            throw new Error('Could not generate or store RSA keys.');
        }
    }
}

// --- AUTH API Endpoints ---
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        const match = await bcrypt.compare(password, user.password);
        if (match) {
            req.session.user = { id: user.id, email: user.email };
            res.status(200).json({ message: 'Login successful' });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ error: 'Server error during login' });
    }
});

app.get('/api/session', (req, res) => {
    if (req.session.user) {
        res.status(200).json({ loggedIn: true, user: req.session.user });
    } else {
        res.status(200).json({ loggedIn: false });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ error: 'Failed to log out' });
        res.clearCookie('connect.sid'); // Default session cookie name
        res.status(200).json({ message: 'Logout successful' });
    });
});

// --- FORMS API Endpoints ---
// Create Form (Admin only, with validation)
// Create Form (Admin only, with validation and file upload)
app.post('/api/forms',
    isAuthenticated,
    upload.single('formFile'), // <-- Add this here!
    [
        body('title').notEmpty().withMessage('Title is required.').trim().isLength({ min: 3 }).withMessage('Title must be at least 3 characters.').escape(),
        body('description').notEmpty().withMessage('Description is required.').trim().isLength({ min: 5 }).withMessage('Description must be at least 5 characters.').escape(),
        body('studentName').notEmpty().withMessage('Student name is required.').trim().escape(),
        body('parentEmail').isEmail().withMessage('Must be a valid email.').normalizeEmail()
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const formDetails = req.body;
        const formId = 'form_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');
        const createdAt = new Date().toISOString();
        const auditTrail = [{ event: 'FORM_CREATED', timestamp: createdAt, ip: req.ip, admin: req.session.user.email }];

        // Handle file info
        let filePath = null;
        let originalFileName = null;
        if (req.file) {
            filePath = req.file.filename; // Save only the filename, not full path
            originalFileName = req.file.originalname;
        }

        try {
            await db.run(
                `INSERT INTO forms (id, title, description, studentName, parentEmail, createdAt, status, auditTrail, filePath, originalFileName) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [formId, formDetails.title, formDetails.description, formDetails.studentName, formDetails.parentEmail, createdAt, 'Pending', JSON.stringify(auditTrail), filePath, originalFileName]
            );
            res.status(201).json({ id: formId, message: 'Form created successfully' });
        } catch (error) {
            console.error("DB error creating form:", error);
            res.status(500).json({ error: 'Failed to create form in database' });
        }
    }
);

// Get All Forms (Admin only)
app.get('/api/forms', isAuthenticated, async (req, res) => {
    try {
        const forms = await db.all(
            'SELECT id, title, studentName, parentEmail, status, signedAt, signedBy, signatureDataUrl, cryptographic_signature IS NOT NULL as isDigitallySigned, auditTrail FROM forms ORDER BY createdAt DESC'
        );
        res.json(forms);
    } catch (error) {
        console.error("DB error fetching forms:", error);
        res.status(500).json({ error: 'Failed to retrieve forms' });
    }
});


// Verify Digital Signature (Admin only)
app.get('/api/forms/:id/verify-signature', isAuthenticated, async (req, res) => {
    const formId = req.params.id;
    try {
        const form = await db.get('SELECT * FROM forms WHERE id = ?', [formId]);
        if (!form) return res.status(404).json({ error: 'Form not found' });
        if (!form.cryptographic_signature || !form.documentHash) {
            return res.status(400).json({ error: 'No digital signature or document hash found for this form.' });
        }
        // Get parent public key
        const keys = await db.get('SELECT public_key FROM parent_rsa_keys WHERE parent_email = ?', [form.parentEmail]);
        if (!keys || !keys.public_key) {
            return res.status(400).json({ error: 'Parent public key not found.' });
        }
        const verify = crypto.createVerify('RSA-SHA256');
        verify.update(form.documentHash);
        verify.end();
        const isValid = verify.verify(keys.public_key, form.cryptographic_signature, 'base64');
        res.json({
            valid: isValid,
            formId,
            parentEmail: form.parentEmail,
            documentHash: form.documentHash,
            cryptographic_signature: form.cryptographic_signature
        });
    } catch (error) {
        console.error('Signature verification error:', error);
        res.status(500).json({ error: 'Failed to verify signature' });
    }
});

// Get Forms for a Specific Parent
app.get('/api/forms/parent/:email', async (req, res) => {
    try {
        const forms = await db.all(
            'SELECT id, title, description, studentName, status, createdAt, filePath, originalFileName FROM forms WHERE parentEmail = ? ORDER BY createdAt DESC',
            [req.params.email.toLowerCase()]
        );
        res.json(forms);
    } catch (error) {
        console.error("DB error fetching parent forms:", error);
        res.status(500).json({ error: 'Failed to retrieve forms' });
    }
});

// Sign Form (Parent - Digital Signature Logic)
app.post('/api/forms/:id/sign', async (req, res) => {
    const formId = req.params.id;
    const { typedSignature, signatureDataUrl } = req.body;

    if (!typedSignature || !signatureDataUrl) {
        return res.status(400).json({ error: 'Typed name and drawn signature are required for visual representation.' });
    }

    try {
        const form = await db.get('SELECT * FROM forms WHERE id = ?', [formId]);
        if (!form) return res.status(404).json({ error: 'Form not found' });
        if (form.status === 'Signed') return res.status(400).json({ error: 'Form already signed' });

        const parentEmail = form.parentEmail;
        if (!parentEmail) return res.status(500).json({ error: 'Parent email missing on form record' });

        const { privateKey } = await getOrGenerateParentRsaKeys(parentEmail);
        if (!privateKey) return res.status(500).json({ error: 'Could not get signing key' });
        
        let documentHash;
        if (form.filePath) {
            try {
                documentHash = await hashUploadedFile(path.join(__dirname, 'uploads', form.filePath));
            } catch (err) {
                return res.status(500).json({ error: 'Could not hash uploaded file for signing' });
            }
        } else {
            documentHash = createDocumentHash(form);
        }
        if (!documentHash) return res.status(500).json({ error: 'Could not create document hash for signing' });

        const sign = crypto.createSign('RSA-SHA256');
        sign.update(documentHash);
        sign.end();
        let auditTrail = [];
        if (form.auditTrail) {
            try {
                auditTrail = JSON.parse(form.auditTrail);
            } catch (e) {
                auditTrail = [];
            }
        }
        auditTrail.push({
            event: 'DIGITALLY_SIGNED',
            timestamp: new Date().toISOString(),
            ip: req.ip,
            parent: parentEmail,
            hash_signed: documentHash
        });

        const cryptographicSignature = sign.sign(privateKey, 'base64');
        const signedAt = new Date().toISOString();
        await db.run(
            `UPDATE forms SET 
                status = ?, signedBy = ?, signedAt = ?, signatureDataUrl = ?, 
                documentHash = ?, cryptographic_signature = ?, auditTrail = ?
             WHERE id = ?`,
            ['Signed', typedSignature, signedAt, signatureDataUrl, 
             documentHash, cryptographicSignature, JSON.stringify(auditTrail), formId]
        );
        res.status(200).json({ message: 'Form signed digitally successfully', formId });
    } catch (error) {
        console.error('Digital signing error:', error);
        // Attempt to update audit trail on error
        try {
            const form = await db.get('SELECT auditTrail FROM forms WHERE id = ?', [formId]);
            if (form && form.auditTrail) {
                let auditTrail = JSON.parse(form.auditTrail);
                auditTrail.push({ event: 'DIGITAL_SIGNATURE_FAILED', timestamp: new Date().toISOString(), ip: req.ip, error: error.message });
                await db.run('UPDATE forms SET auditTrail = ? WHERE id = ?', [JSON.stringify(auditTrail), formId]);
            }
        } catch (auditError) { console.error('Failed to update audit trail on error:', auditError); }
        res.status(500).json({ error: 'Failed to digitally sign form' });
    }
});


// --- Start Server ---
async function startServer() {
    try {
        db = await setupDatabase(); // Initialize db connection
        app.listen(port, () => {
            console.log(`✅ Server running at http://localhost:${port}`);
            console.log('   Open your browser to use the app.');
            console.log('   Make sure you have run `node create-admin.js` if this is the first setup.');
            console.log('   IMPORTANT: Change the default `SESSION_SECRET` in server.js for any real use!');
        });
    } catch (error) {
        console.error("❌ Failed to start server or setup database:", error);
    }
}

startServer();