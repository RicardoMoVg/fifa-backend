const { Pool } = require('pg');

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'mundial_2026',
    password: '12345',
    port: 5432,
});

const checkColumns = async () => {
    try {
        const res = await pool.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'users' 
            AND column_name IN ('email', 'password_hash');
        `);
        console.log('Found columns:', res.rows.map(r => r.column_name));
    } catch (err) {
        console.error('Error:', err);
    } finally {
        pool.end();
    }
};

checkColumns();
