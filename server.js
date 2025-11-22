// backend/server.js - VERSIÓN CORREGIDA Y SEGURA

// 1. IMPORTACIONES DE MÓDULOS
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

// 2. CONFIGURACIÓN INICIAL
const app = express();
app.use(express.json());

// SEGURIDAD: JWT_SECRET desde variable de entorno
const JWT_SECRET = process.env.JWT_SECRET || 'este-es-un-secreto-muy-largo-y-seguro-que-debes-cambiar';
const PORT = process.env.PORT || 4000;

// 3. CONFIGURACIÓN DE LA BASE DE DATOS
const isProduction = process.env.NODE_ENV === 'production' || (process.env.DB_HOST && process.env.DB_HOST !== 'localhost');

const pool = new Pool({
    connectionString: process.env.INTERNAL_DATABASE_URL || undefined,
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || '12345',
    database: process.env.DB_NAME || 'mundial_2026',
    port: process.env.DB_PORT || 5432,
    ssl: isProduction ? { rejectUnauthorized: false } : false
});

pool.connect((err) => {
    if (err) {
        console.error('❌ Error CRÍTICO al conectar con la base de datos:', err.message);
    } else {
        console.log('✅ Conexión exitosa a la base de datos PostgreSQL (' + (isProduction ? 'Nube' : 'Local') + ').');
    }
});

// 4. MIDDLEWARE DE AUTENTICACIÓN
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// 5. CONFIGURACIÓN DE CORS (CORREGIDO - Solo una vez)
const allowedOrigins = [
    "http://localhost:5173",
    "http://localhost:3000",
    "https://frontend-kgb9esxzd-charlies-projects-1a4acc00.vercel.app"
];

app.use(cors({
    origin: allowedOrigins,
    credentials: true
}));

// 6. ENDPOINTS DE LA API (RUTAS HTTP)
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ message: 'Por favor, completa todos los campos.' });
    try {
        const salt = await bcrypt.genSalt(10);
        const password_hash = await bcrypt.hash(password, salt);
        const result = await pool.query('INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username', [username, email, password_hash]);
        res.status(201).json({ message: '¡Cuenta creada con éxito!', user: result.rows[0] });
    } catch (err) {
        if (err.code === '23505') return res.status(409).json({ message: 'El email o nombre de usuario ya está en uso.' });
        console.error('❌ Error en el registro:', err);
        res.status(500).json({ message: 'Error interno del servidor.', error: err.message });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Por favor, completa todos los campos.' });
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(401).json({ message: 'Credenciales inválidas.' });
        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash || user.password_has);
        if (!isMatch) return res.status(401).json({ message: 'Credenciales inválidas.' });
        const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ message: 'Inicio de sesión exitoso', token, user: { id: user.id, username: user.username } });
    } catch (err) {
        console.error('❌ Error en el inicio de sesión:', err);
        res.status(500).json({ message: 'Error interno del servidor.', error: err.message });
    }
});

app.get('/api/users', authenticateToken, async (req, res) => {
    try {
        const currentUserId = req.user.userId;
        const result = await pool.query('SELECT id, username FROM users WHERE id != $1 ORDER BY username ASC', [currentUserId]);
        res.status(200).json(result.rows);
    } catch (err) {
        console.error('❌ Error al obtener la lista de usuarios:', err);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

app.get('/api/messages/:room', authenticateToken, async (req, res) => {
    try {
        const { room } = req.params;
        const query = `
            SELECT m.id, m.content as text, m.sent_at as time, m.image_url, u.id as "userId", u.username as user
            FROM messages m JOIN users u ON m.user_id = u.id
            WHERE m.group_id = $1 ORDER BY m.sent_at ASC;`;
        const result = await pool.query(query, [room]);
        res.status(200).json(result.rows);
    } catch (err) {
        console.error('❌ Error al obtener el historial de mensajes:', err);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

app.post('/api/chat/private/initiate', authenticateToken, async (req, res) => {
    const initiatorUserId = req.user.userId;
    const { targetUserId } = req.body;

    if (!targetUserId) {
        return res.status(400).json({ message: 'Falta el ID del usuario destino (targetUserId).' });
    }

    if (initiatorUserId === targetUserId) {
        return res.status(400).json({ message: 'No puedes iniciar un chat contigo mismo.' });
    }

    const client = await pool.connect();

    try {
        const findGroupQuery = `
            SELECT gm.group_id
            FROM group_members gm
            JOIN groups g ON gm.group_id = g.id
            WHERE g.is_private = true
              AND gm.user_id IN ($1, $2)
            GROUP BY gm.group_id
            HAVING COUNT(DISTINCT gm.user_id) = 2
            LIMIT 1;
        `;
        const groupResult = await client.query(findGroupQuery, [initiatorUserId, targetUserId]);

        if (groupResult.rows.length > 0) {
            const existingGroupId = groupResult.rows[0].group_id;
            console.log(`✅ Chat privado encontrado entre ${initiatorUserId} y ${targetUserId}. ID: ${existingGroupId}`);
            res.status(200).json({ groupId: existingGroupId });
        } else {
            await client.query('BEGIN');

            const createGroupQuery = `
                INSERT INTO groups (name, creator_id, is_private)
                VALUES ($1, $2, true)
                RETURNING id;
            `;
            const groupName = `Chat Privado ${initiatorUserId}-${targetUserId}`;
            const newGroupResult = await client.query(createGroupQuery, [groupName, initiatorUserId]);
            const newGroupId = newGroupResult.rows[0].id;

            const addMembersQuery = `
                INSERT INTO group_members (user_id, group_id) VALUES ($1, $2), ($3, $2);
            `;
            await client.query(addMembersQuery, [initiatorUserId, newGroupId, targetUserId]);

            await client.query('COMMIT');

            console.log(`✅ Nuevo chat privado creado entre ${initiatorUserId} y ${targetUserId}. ID: ${newGroupId}`);
            res.status(201).json({ groupId: newGroupId });
        }

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('❌ Error al iniciar/obtener chat privado:', err);
        res.status(500).json({ message: 'Error interno del servidor al gestionar chat privado.' });
    } finally {
        client.release();
    }
});

app.get('/api/matches', authenticateToken, async (req, res) => {
    try {
        const query = `
            SELECT m.id, m.status, m.score_local, m.score_visitor, m.match_date,
                   t1.name as local_team_name, t2.name as visitor_team_name
            FROM matches m
            JOIN teams t1 ON m.local_team_id = t1.id
            JOIN teams t2 ON m.visitor_team_id = t2.id
            ORDER BY m.match_date ASC;
        `;
        const result = await pool.query(query);
        res.status(200).json(result.rows);
    } catch (err) {
        console.error('❌ Error al obtener la lista de partidos:', err);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

app.post('/api/matches/simulate/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query("UPDATE matches SET status = 'live' WHERE id = $1", [id]);
        startSimulation(parseInt(id));
        res.status(200).json({ message: `Simulación del partido ${id} iniciada.` });
    } catch (err) {
        console.error(`❌ Error al iniciar simulación para el partido ${id}:`, err);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// CONFIGURACIÓN DE NODEMAILER (Movido fuera de socket.io)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// ENDPOINT PARA ENVIAR CORREO (Movido fuera de socket.io)
app.post('/api/email/send', authenticateToken, async (req, res) => {
    const { targetUserId, subject, message } = req.body;
    const senderEmail = process.env.EMAIL_USER;

    if (!targetUserId || !subject || !message) {
        return res.status(400).json({ message: 'Faltan datos.' });
    }

    try {
        const userRes = await pool.query('SELECT email, username FROM users WHERE id = $1', [targetUserId]);

        if (userRes.rows.length === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado.' });
        }

        const targetEmail = userRes.rows[0].email;
        const targetName = userRes.rows[0].username;

        const mailOptions = {
            from: `"Simulador FIFA 2026" <${senderEmail}>`,
            to: targetEmail,
            subject: `Mensaje de ${req.user.username}: ${subject}`,
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                    <h2 style="color: #0066b3;">¡Hola ${targetName}!</h2>
                    <p>El usuario <strong>${req.user.username}</strong> te ha enviado un mensaje desde la plataforma:</p>
                    <hr>
                    <p style="font-size: 16px; color: #333;">${message}</p>
                    <hr>
                    <small style="color: #888;">No respondas a este correo directamente.</small>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);
        res.json({ message: 'Correo enviado exitosamente.' });

    } catch (error) {
        console.error("Error enviando correo:", error);
        res.status(500).json({ message: 'Error al enviar el correo.' });
    }
});

// ENDPOINTS DE SETUP (Protegidos - Solo para desarrollo)
if (process.env.NODE_ENV !== 'production') {
    app.get('/setup-database', async (req, res) => {
        try {
            await pool.query(`
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    email VARCHAR(100) UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    is_online BOOLEAN DEFAULT FALSE,
                    points INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS groups (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100),
                    description TEXT,
                    is_private BOOLEAN DEFAULT FALSE,
                    creator_id INTEGER REFERENCES users(id),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS group_members (
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE,
                    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (user_id, group_id)
                );

                CREATE TABLE IF NOT EXISTS messages (
                    id SERIAL PRIMARY KEY,
                    content TEXT,
                    image_url TEXT,
                    user_id INTEGER REFERENCES users(id),
                    group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE,
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS tasks (
                    id SERIAL PRIMARY KEY,
                    description TEXT NOT NULL,
                    is_completed BOOLEAN DEFAULT FALSE,
                    group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS teams (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(50) NOT NULL,
                    rating INTEGER DEFAULT 70,
                    discipline INTEGER DEFAULT 80
                );

                CREATE TABLE IF NOT EXISTS stadiums (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100),
                    factor_clima VARCHAR(20)
                );

                CREATE TABLE IF NOT EXISTS matches (
                    id SERIAL PRIMARY KEY,
                    local_team_id INTEGER REFERENCES teams(id),
                    visitor_team_id INTEGER REFERENCES teams(id),
                    score_local INTEGER DEFAULT 0,
                    score_visitor INTEGER DEFAULT 0,
                    status VARCHAR(20) DEFAULT 'scheduled',
                    stadium_id INTEGER REFERENCES stadiums(id),
                    match_date TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS match_logs (
                    id SERIAL PRIMARY KEY,
                    match_id INTEGER REFERENCES matches(id) ON DELETE CASCADE,
                    minute INTEGER,
                    event_text TEXT
                );

                CREATE TABLE IF NOT EXISTS user_badges (
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    badge_code VARCHAR(50),
                    awarded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            `);

            await pool.query(`
                INSERT INTO teams (name, rating) VALUES 
                ('Argentina', 95), ('Francia', 94), ('Brasil', 93), 
                ('México', 80), ('Alemania', 88), ('Japón', 78),
                ('España', 89), ('Inglaterra', 90)
                ON CONFLICT DO NOTHING;

                INSERT INTO stadiums (name, factor_clima) VALUES 
                ('Estadio Azteca', 'calor'), ('Wembley', 'lluvia'), ('Lusail', 'soleado')
                ON CONFLICT DO NOTHING;
            `);

            res.send(`
                <div style="font-family: sans-serif; text-align: center; padding: 50px;">
                    <h1 style="color: green;">✅ Base de Datos Instalada Correctamente</h1>
                    <p>Se han creado las tablas: users, groups, messages, tasks, teams, matches, etc.</p>
                    <p>Ya puedes usar la aplicación.</p>
                </div>
            `);

        } catch (err) {
            console.error(err);
            res.status(500).send(`
                <div style="font-family: sans-serif; text-align: center; padding: 50px;">
                    <h1 style="color: red;">❌ Error en la instalación</h1>
                    <p>${err.message}</p>
                </div>
            `);
        }
    });
}

// 7. CONFIGURACIÓN DEL SERVIDOR Y SOCKET.IO
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: allowedOrigins,
        methods: ["GET", "POST"],
        credentials: true
    }
});

// MAPA DE USUARIOS CONECTADOS (RESTAURADO)
const userSocketMap = {};

// 8. MOTOR DE SIMULACIÓN DE PARTIDOS
const activeSimulations = {};

function stopSimulation(matchId) {
    if (activeSimulations[matchId] && activeSimulations[matchId].intervalId) {
        clearTimeout(activeSimulations[matchId].intervalId);
        delete activeSimulations[matchId];
        console.log(`⏹️ Simulación para el partido ${matchId} detenida.`);
    }
}

async function startSimulation(matchId) {
    if (activeSimulations[matchId]) return;
    console.log(`▶️ Iniciando simulación para el partido ${matchId}...`);

    try {
        const matchQuery = `
            SELECT m.*, s.factor_clima, s.name as stadium_name
            FROM matches m
            LEFT JOIN stadiums s ON m.stadium_id = s.id
            WHERE m.id = $1;
        `;
        const matchRes = await pool.query(matchQuery, [matchId]);
        if (matchRes.rows.length === 0) throw new Error('Partido no encontrado');
        const match = matchRes.rows[0];

        const teamsRes = await pool.query('SELECT * FROM teams WHERE id = $1 OR id = $2', [match.local_team_id, match.visitor_team_id]);
        const localTeam = teamsRes.rows.find(t => t.id === match.local_team_id);
        const visitorTeam = teamsRes.rows.find(t => t.id === match.visitor_team_id);

        const simulationState = {
            matchId: matchId,
            currentMinute: 0,
            score_local: 0,
            score_visitor: 0,
            climate: match.factor_clima,
            pressure: 1.0,
            localTeam: {
                id: localTeam.id,
                name: localTeam.name,
                baseRating: localTeam.rating,
                moral: 100,
                discipline: localTeam.discipline,
                discipline_penalty: 0,
                isHome: true,
            },
            visitorTeam: {
                id: visitorTeam.id,
                name: visitorTeam.name,
                baseRating: visitorTeam.rating,
                moral: 100,
                discipline: visitorTeam.discipline,
                discipline_penalty: 0,
                isHome: false,
            },
            intervalId: null
        };

        activeSimulations[matchId] = simulationState;
        simulateTick(matchId);

    } catch (err) {
        console.error(`❌ Error al iniciar simulación para el partido ${matchId}:`, err);
    }
}

async function simulateTick(matchId) {
    const state = activeSimulations[matchId];
    if (!state) return stopSimulation(matchId);

    state.currentMinute++;
    const roomName = `match-chat-${matchId}`;

    let eventText = `Minuto ${state.currentMinute}: El partido sigue disputado en el mediocampo.`;

    try {
        const room = io.sockets.adapter.rooms.get(roomName);
        const userCount = room ? room.size : 0;
        const chatMoralBonus = Math.floor(userCount / 5);
        state.localTeam.moral = Math.min(150, state.localTeam.moral + chatMoralBonus);
        state.visitorTeam.moral = Math.min(150, state.visitorTeam.moral + chatMoralBonus);

        let localStadiumBoost = state.localTeam.isHome ? 5 : 0;
        let climatePenalty = (state.climate === 'calor' || state.climate === 'lluvia') ? 3 : 0;

        const powerLocal = (state.localTeam.baseRating + state.localTeam.moral + localStadiumBoost - state.localTeam.discipline_penalty - climatePenalty) * state.pressure;
        const powerVisitor = (state.visitorTeam.baseRating + state.visitorTeam.moral - state.visitorTeam.discipline_penalty - climatePenalty) * state.pressure;
        const totalPower = Math.max(1, powerLocal + powerVisitor);

        const rand = Math.random();
        const localChance = powerLocal / totalPower;

        const CHANCE_GOAL = 0.05;
        const CHANCE_YELLOW = 0.03;
        const CHANCE_RED = 0.01;
        const CHANCE_SURPRISE = 0.02;

        if (rand < CHANCE_GOAL) {
            if (Math.random() < localChance) {
                state.score_local++;
                eventText = `¡GOL de ${state.localTeam.name}!`;
                state.visitorTeam.moral -= 10;
            } else {
                state.score_visitor++;
                eventText = `¡GOL de ${state.visitorTeam.name}!`;
                state.localTeam.moral -= 10;
            }
            await pool.query('UPDATE matches SET score_local = $1, score_visitor = $2 WHERE id = $3', [state.score_local, state.score_visitor, matchId]);

        } else if (rand < CHANCE_GOAL + CHANCE_YELLOW) {
            const disciplineRatio = state.localTeam.discipline / (state.localTeam.discipline + state.visitorTeam.discipline);
            if (Math.random() < disciplineRatio) {
                state.localTeam.discipline_penalty += 5;
                eventText = `Tarjeta amarilla para ${state.localTeam.name}.`;
            } else {
                state.visitorTeam.discipline_penalty += 5;
                eventText = `Tarjeta amarilla para ${state.visitorTeam.name}.`;
            }

        } else if (rand < CHANCE_GOAL + CHANCE_YELLOW + CHANCE_RED) {
            const disciplineRatio = state.localTeam.discipline / (state.localTeam.discipline + state.visitorTeam.discipline);
            if (Math.random() < disciplineRatio) {
                state.localTeam.discipline_penalty += 20;
                eventText = `¡TARJETA ROJA! ${state.localTeam.name} se queda con 10.`;
            } else {
                state.visitorTeam.discipline_penalty += 20;
                eventText = `¡TARJETA ROJA! ${state.visitorTeam.name} se queda con 10.`;
            }

        } else if (rand < CHANCE_GOAL + CHANCE_YELLOW + CHANCE_RED + CHANCE_SURPRISE) {
            if (userCount > 10) {
                if (Math.random() < localChance) {
                    state.localTeam.moral += 15;
                    eventText = `¡${state.localTeam.name} realiza una jugada increíble! ¡La afición (chat) reacciona!`;
                } else {
                    state.visitorTeam.moral += 15;
                    eventText = `¡${state.visitorTeam.name} sorprende con una gran jugada!`;
                }
            }
        }

        await pool.query('INSERT INTO match_logs (match_id, minute, event_text) VALUES ($1, $2, $3)', [matchId, state.currentMinute, eventText]);

        io.to(roomName).emit('match-update', {
            score_local: state.score_local,
            score_visitor: state.score_visitor,
            last_event: { minute: state.currentMinute, text: eventText },
            user_count: userCount,
            local_moral: state.localTeam.moral,
            visitor_moral: state.visitorTeam.moral
        });

        if (state.currentMinute >= 90) {
            await pool.query("UPDATE matches SET status = 'finished' WHERE id = $1", [matchId]);
            stopSimulation(matchId);
            io.to(roomName).emit('match-finished', {
                message: "¡Partido finalizado!",
                final_score: { local: state.score_local, visitor: state.score_visitor }
            });
        } else {
            state.intervalId = setTimeout(() => simulateTick(matchId), 2000);
            activeSimulations[matchId] = state;
        }

    } catch (err) {
        console.error(`❌ Error en el tick de simulación para el partido ${matchId}:`, err);
        stopSimulation(matchId);
    }
}

// 9. LÓGICA DE SOCKET.IO (CHAT EN TIEMPO REAL)
io.on('connection', (socket) => {
    console.log(`🔌 Usuario conectado al chat: ${socket.id}`);
    let currentRoom = '';

    socket.on('registerUser', async (userId) => {
        socket.userId = userId;
        userSocketMap[userId] = socket.id;
        console.log(`Usuario ${userId} registrado con socket ${socket.id}`);
        try {
            const result = await pool.query(`
                SELECT g.id, g.name, g.description FROM groups g
                JOIN group_members gm ON g.id = gm.group_id WHERE gm.user_id = $1;`, [userId]);
            socket.emit('initialGroupList', result.rows);
        } catch (err) { console.error("Error al obtener grupos:", err); }
    });

    socket.on('joinRoom', async (room) => {
        const userId = socket.userId;

        if (!userId) {
            return socket.emit('error', 'No estás autenticado en el chat.');
        }

        let hasPermission = false;

        if (!isNaN(room)) {
            try {
                const result = await pool.query(
                    'SELECT 1 FROM group_members WHERE user_id = $1 AND group_id = $2',
                    [userId, room]
                );
                if (result.rows.length > 0) hasPermission = true;
            } catch (err) {
                console.error('Error validando grupo:', err);
            }
        } else if (typeof room === 'string') {
            if (room.startsWith('match-chat-')) {
                hasPermission = true;
            }
        }

        if (!hasPermission) {
            console.log(`⛔ Acceso denegado: Usuario ${userId} intentó entrar a sala ${room}`);
            return socket.emit('error', 'No tienes permiso para entrar a esta sala.');
        }

        if (currentRoom) socket.leave(currentRoom);
        socket.join(room);
        currentRoom = room;
        console.log(`✅ Usuario ${userId} (Socket ${socket.id}) se unió a la sala: ${room}`);
    });

    socket.on('sendMessage', async (data) => {
        if (currentRoom !== data.room) {
            return socket.emit('error', 'No puedes enviar mensajes a una sala en la que no estás.');
        }

        try {
            const { text, userId, room, image } = data;

            if (!isNaN(room)) {
                await pool.query(
                    'INSERT INTO messages (content, user_id, group_id, image_url) VALUES ($1, $2, $3, $4)',
                    [text || '', userId, room, image || null]
                );
            }
            io.to(room).emit('receiveMessage', data);
        } catch (err) { console.error('❌ Error al procesar mensaje:', err); }
    });

    socket.on('createGroup', async (groupData) => {
        const { name, members, creatorId } = groupData;
        try {
            const groupResult = await pool.query('INSERT INTO groups (name, creator_id, description) VALUES ($1, $2, $3) RETURNING *', [name, creatorId, `Grupo de ${members.length} miembros`]);
            const newGroup = groupResult.rows[0];

            await pool.query('INSERT INTO group_members (user_id, group_id) VALUES ($1, $2)', [creatorId, newGroup.id]);

            for (const memberId of members) {
                await pool.query('INSERT INTO group_members (user_id, group_id) VALUES ($1, $2)', [memberId, newGroup.id]);
            }
            console.log(`✅ Grupo "${newGroup.name}" creado en la BD.`);
            const groupInfoForClient = { id: newGroup.id, name: newGroup.name, description: newGroup.description };

            const creatorSocketId = userSocketMap[creatorId];
            if (creatorSocketId) io.to(creatorSocketId).emit('newGroupAdded', groupInfoForClient);

            members.forEach(memberId => {
                const memberSocketId = userSocketMap[memberId];
                if (memberSocketId) io.to(memberSocketId).emit('newGroupAdded', groupInfoForClient);
            });
        } catch (err) { console.error("Error al crear grupo en BD:", err); }
    });

    socket.on('solicitud-de-llamada', (data) => {
        const { targetId, room, from } = data;
        const targetSocketId = userSocketMap[targetId];
        if (targetSocketId) {
            console.log(` reenviando llamada de ${from.username} a ${targetId}`);
            io.to(targetSocketId).emit('llamada-entrante', { from, room });
        }
    });

    socket.on('llamada-aceptada', (data) => {
        io.to(data.toSocketId).emit('llamada-fue-aceptada', { room: data.room });
    });

    socket.on('llamada-rechazada', (data) => {
        io.to(data.toSocketId).emit('llamada-fue-rechazada');
    });

    socket.on('join-video-room', (roomName) => {
        socket.join(roomName);
        socket.to(roomName).emit('user-joined', socket.id);
    });

    socket.on('offer', (payload) => io.to(payload.target).emit('offer', payload));
    socket.on('answer', (payload) => io.to(payload.target).emit('answer', payload));
    socket.on('ice-candidate', (incoming) => io.to(incoming.target).emit('ice-candidate', incoming.candidate));

    socket.on('disconnect', () => {
        for (const userId in userSocketMap) {
            if (userSocketMap[userId] === socket.id) {
                delete userSocketMap[userId];
                console.log(`🧹 Usuario ${userId} eliminado del mapa.`);
                break;
            }
        }
        console.log(`🔌 Usuario desconectado del chat: ${socket.id}`);
    });

    socket.on('join-match-chat', (matchId) => {
        const roomName = `match-chat-${matchId}`;
        socket.join(roomName);
        console.log(`Usuario ${socket.id} se unió a la transmisión del partido ${matchId}`);
    });

    socket.on('leave-match-chat', (matchId) => {
        const roomName = `match-chat-${matchId}`;
        socket.leave(roomName);
        console.log(`Usuario ${socket.id} abandonó la transmisión del partido ${matchId}`);
    });
});

// 10. INICIAR EL SERVIDOR
server.listen(PORT, () => {
    console.log(`🚀 Servidor escuchando en el puerto ${PORT}`);
    console.log(`🔒 Modo: ${isProduction ? 'PRODUCCIÓN' : 'DESARROLLO'}`);
    console.log(`🌐 CORS permitido para: ${allowedOrigins.join(', ')}`);
});