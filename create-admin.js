const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const bcrypt = require('bcrypt');

async function createAdmin() {
    console.log('Attempting to connect to database for admin creation...');
    let db;
    try {
        db = await open({
            filename: './permissions.db',
            driver: sqlite3.Database
        });
    } catch (error) {
        console.error('❌ Failed to connect to the database. Make sure server.js has run at least once to create permissions.db', error);
        return;
    }

    const email = 'admin@school.com'; // CHANGE THIS to your desired admin email
    const password = 'YOUR_STRONG_PASSWORD'; // CHANGE THIS to a strong password
    const saltRounds = 10;

    if (password === 'YOUR_STRONG_PASSWORD') {
        console.warn('⚠️ WARNING: Please change the default password in create-admin.js before running this in any sensitive environment.');
        // return; // You might want to uncomment this to force password change
    }


    console.log(`Hashing password for ${email}...`);
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    console.log('Inserting admin user into database...');
    try {
        await db.run(
            'INSERT INTO users (email, password) VALUES (?, ?)',
            [email, hashedPassword]
        );
        console.log('✅ Admin user created successfully!');
        console.log(`   Email: ${email}`);
        console.log(`   You can now log in with the password you chose.`);
    } catch (error) {
        if (error.message.includes('UNIQUE constraint failed: users.email')) {
            console.warn(`⚠️ Admin user with email ${email} already exists.`);
        } else if (error.message.includes('no such table: users')) {
            console.error('❌ Error: The "users" table does not exist. Please ensure you run `node server.js` first to create the database schema, then stop it, and then run this script.');
        } 
        else {
            console.error('❌ An unexpected error occurred during admin creation:', error.message);
        }
    }

    if (db) {
        await db.close();
    }
}

createAdmin();