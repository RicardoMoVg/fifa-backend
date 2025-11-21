const { Pool } = require('pg');

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'mundial_2026',
    password: '12345',
    port: 5432,
});

pool.query('SELECT NOW()', (err, res) => {
    if (err) {
        console.error('Connection Error:', err);
        process.exit(1);
    } else {
        console.log('Connection Successful:', res.rows[0]);
        process.exit(0);
    }
});
