const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');

async function setup() {
    const db = await open({
        filename: './permissions.db', // Database file will be created in project root
        driver: sqlite3.Database
    });

    // Forms table with new columns for digital signature
    await db.exec(`
        CREATE TABLE IF NOT EXISTS forms (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            studentName TEXT NOT NULL,
            parentEmail TEXT NOT NULL,
            createdAt TEXT NOT NULL,
            status TEXT NOT NULL,          -- Pending, Signed
            signedBy TEXT,                 -- Typed name of signer (for display)
            signedAt TEXT,                 -- Timestamp of signing
            signatureDataUrl TEXT,         -- Drawn signature image (for display)
            documentHash TEXT,             -- Hash of form content at time of signing
            auditTrail TEXT,               -- JSON array of events
            cryptographic_signature TEXT   -- The RSA digital signature (hex/base64)
        )
    `);

    // Users table for admin authentication
    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL       -- Hashed password
        )
    `);

    // Table for storing parent RSA keys (simplified for educational project)
    await db.exec(`
        CREATE TABLE IF NOT EXISTS parent_rsa_keys (
            parent_email TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,     -- PEM formatted public key
            private_key TEXT NOT NULL     -- PEM formatted private key (SECURITY NOTE: Storing raw private keys server-side is risky in production)
        )
    `);

    console.log('Database setup complete: forms, users, and parent_rsa_keys tables are ready.');
    return db;
}

module.exports = setup;