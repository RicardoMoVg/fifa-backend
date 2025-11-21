const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'mundial_2026',
    password: '12345',
    port: 5432,
});

const testRegister = async () => {
    const username = 'testuser_' + Date.now();
    const email = 'test_' + Date.now() + '@example.com';
    const password = 'password123';

    try {
        console.log('Hashing password...');
        const salt = await bcrypt.genSalt(10);
        const password_hash = await bcrypt.hash(password, salt);
        console.log('Password hashed.');

        console.log('Inserting user...');
        const result = await pool.query('INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username', [username, email, password_hash]);
        console.log('User inserted:', result.rows[0]);
    } catch (err) {
        console.error('Error during registration simulation:', err);
    } finally {
        pool.end();
    }
};

testRegister();
