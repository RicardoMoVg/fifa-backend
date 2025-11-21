const { Pool } = require('pg');

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'mundial_2026',
    password: '12345',
    port: 5432,
});

const checkTable = async () => {
    try {
        const res = await pool.query("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'users';");
        console.log('Columns in users table:', res.rows);
        if (res.rows.length === 0) {
            console.log('Table "users" does not exist.');
        }
    } catch (err) {
        console.error('Error querying schema:', err);
    } finally {
        pool.end();
    }
};

checkTable();
