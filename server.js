// backend/server.js - VERSIÓN FINAL Y COMPLETA

// 1. IMPORTACIONES DE MÓDULOS
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// 2. CONFIGURACIÓN INICIAL
const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = 'este-es-un-secreto-muy-largo-y-seguro-que-debes-cambiar';
const PORT = process.env.PORT || 4000;

// 3. CONFIGURACIÓN DE LA BASE DE DATOS
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'mundial_2026',
    password: '12345',
    port: 5432,
});

pool.query('SELECT NOW()', (err) => {
    if (err) console.error('❌ Error al conectar con la base de datos:', err.stack);
    else console.log('✅ Conexión a la base de datos "mundial_2026" exitosa.');
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

// 5. ENDPOINTS DE LA API (RUTAS HTTP)
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
            SELECT m.id, m.content as text, m.sent_at as time, u.id as "userId", u.username as user
            FROM messages m JOIN users u ON m.user_id = u.id
            WHERE m.group_id = $1 ORDER BY m.sent_at ASC;`;
        const result = await pool.query(query, [room]);
        res.status(200).json(result.rows);
    } catch (err) {
        console.error('❌ Error al obtener el historial de mensajes:', err);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// NUEVO ENDPOINT PARA INICIAR/OBTENER CHAT PRIVADO
app.post('/api/chat/private/initiate', authenticateToken, async (req, res) => {
    const initiatorUserId = req.user.userId; // ID del usuario que inicia el chat (del token)
    const { targetUserId } = req.body; // ID del usuario con quien se quiere chatear

    if (!targetUserId) {
        return res.status(400).json({ message: 'Falta el ID del usuario destino (targetUserId).' });
    }

    if (initiatorUserId === targetUserId) {
        return res.status(400).json({ message: 'No puedes iniciar un chat contigo mismo.' });
    }

    const client = await pool.connect(); // Usaremos un cliente para transacciones

    try {
        // PASO 1: Buscar si ya existe un grupo privado entre estos dos usuarios
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
            // Ya existe un grupo privado, devolvemos su ID
            const existingGroupId = groupResult.rows[0].group_id;
            console.log(`✅ Chat privado encontrado entre ${initiatorUserId} y ${targetUserId}. ID: ${existingGroupId}`);
            res.status(200).json({ groupId: existingGroupId });
        } else {
            // PASO 2: No existe, creamos uno nuevo DENTRO DE UNA TRANSACCIÓN
            await client.query('BEGIN'); // Iniciar transacción

            // Crear el grupo
            const createGroupQuery = `
                INSERT INTO groups (name, creator_id, is_private)
                VALUES ($1, $2, true)
                RETURNING id;
            `;
            // Podrías generar un nombre más descriptivo si quisieras
            const groupName = `Chat Privado ${initiatorUserId}-${targetUserId}`;
            const newGroupResult = await client.query(createGroupQuery, [groupName, initiatorUserId]);
            const newGroupId = newGroupResult.rows[0].id;

            // Añadir ambos miembros al grupo
            const addMembersQuery = `
                INSERT INTO group_members (user_id, group_id) VALUES ($1, $2), ($3, $2);
            `;
            await client.query(addMembersQuery, [initiatorUserId, newGroupId, targetUserId]);

            await client.query('COMMIT'); // Finalizar transacción si todo fue bien

            console.log(`✅ Nuevo chat privado creado entre ${initiatorUserId} y ${targetUserId}. ID: ${newGroupId}`);
            res.status(201).json({ groupId: newGroupId }); // 201 Created
        }

    } catch (err) {
        await client.query('ROLLBACK'); // Deshacer transacción en caso de error
        console.error('❌ Error al iniciar/obtener chat privado:', err);
        res.status(500).json({ message: 'Error interno del servidor al gestionar chat privado.' });
    } finally {
        client.release(); // Liberar el cliente de la pool
    }
});

// --- FIN DEL NUEVO ENDPOINT ---

// ENDPOINT PARA OBTENER LA LISTA DE PARTIDOS
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

// ENDPOINT PARA INICIAR LA SIMULACIÓN DE UN PARTIDO (solo para admins en un futuro)
app.post('/api/matches/simulate/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query("UPDATE matches SET status = 'live' WHERE id = $1", [id]);
        startSimulation(parseInt(id)); // Inicia el motor de simulación para este partido
        res.status(200).json({ message: `Simulación del partido ${id} iniciada.` });
    } catch (err) {
        console.error(`❌ Error al iniciar simulación para el partido ${id}:`, err);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// 6. CONFIGURACIÓN DEL SERVIDOR Y SOCKET.IO
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: [
            "http://localhost:5173",
            "http://localhost:3000",
            // Añade tu dominio de Vercel cuando lo tengas:
            // "https://tu-proyecto-fifa.vercel.app"
        ],
        methods: ["GET", "POST"],
        credentials: true
    }
});
const userSocketMap = {};

// AÑADIR ESTE BLOQUE ANTES DE LA LÓGICA DE SOCKET.IO

// --- 6. MOTOR DE SIMULACIÓN DE PARTIDOS (Versión PDF) ---

// activeSimulations guardará el ESTADO COMPLETO de cada partido en vivo.
const activeSimulations = {};

/**
 * Detiene el intervalo de simulación y limpia la memoria.
 */
function stopSimulation(matchId) {
    if (activeSimulations[matchId] && activeSimulations[matchId].intervalId) {
        // CAMBIO: Ahora limpiamos un setTimeout, no un setInterval
        // Usamos clearTimeout en lugar de clearInterval
        clearTimeout(activeSimulations[matchId].intervalId);
        delete activeSimulations[matchId];
        console.log(`⏹️ Simulación para el partido ${matchId} detenida.`);
    }
}

/**
 * Inicia la simulación.
 * (Esta es la NUEVA versión de startSimulation)
 */
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

        // Llamamos al primer tick
        simulateTick(matchId);

    } catch (err) {
        console.error(`❌ Error al iniciar simulación para el partido ${matchId}:`, err);
    }
}


/**
 * El corazón del motor de simulación.
 * (Esta es la NUEVA versión de simulateTick)
 */
async function simulateTick(matchId) {
    const state = activeSimulations[matchId];
    if (!state) return stopSimulation(matchId);

    state.currentMinute++;
    const roomName = `match-chat-${matchId}`;

    let eventText = `Minuto ${state.currentMinute}: El partido sigue disputado en el mediocampo.`;

    try {
        // 1. CALCULAR PODER ACTUAL
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

        // 2. GENERAR EVENTOS
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
            // Evento: Tarjeta Roja
            const disciplineRatio = state.localTeam.discipline / (state.localTeam.discipline + state.visitorTeam.discipline);
            if (Math.random() < disciplineRatio) {
                state.localTeam.discipline_penalty += 20; // Penalidad mayor
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

        // 3. ACTUALIZAR MARCADOR Y GUARDAR LOG
        await pool.query('INSERT INTO match_logs (match_id, minute, event_text) VALUES ($1, $2, $3)', [matchId, state.currentMinute, eventText]);

        io.to(roomName).emit('match-update', {
            score_local: state.score_local,
            score_visitor: state.score_visitor,
            last_event: { minute: state.currentMinute, text: eventText },
            user_count: userCount,
            local_moral: state.localTeam.moral,
            visitor_moral: state.visitorTeam.moral
        });

        // 4. FINALIZAR O CONTINUAR
        if (state.currentMinute >= 90) {
            await pool.query("UPDATE matches SET status = 'finished' WHERE id = $1", [matchId]);
            stopSimulation(matchId);
            io.to(roomName).emit('match-finished', {
                message: "¡Partido finalizado!",
                final_score: { local: state.score_local, visitor: state.score_visitor }
            });
        } else {
            // Agendamos el próximo tick
            state.intervalId = setTimeout(() => simulateTick(matchId), 2000);
            activeSimulations[matchId] = state;
        }

    } catch (err) {
        console.error(`❌ Error en el tick de simulación para el partido ${matchId}:`, err);
        stopSimulation(matchId);
    }
}

// 7. LÓGICA DE SOCKET.IO (CHAT EN TIEMPO REAL)
io.on('connection', (socket) => {
    console.log(`🔌 Usuario conectado al chat: ${socket.id}`);
    let currentRoom = '';

    // --- Lógica de Chat y Grupos ---
    socket.on('registerUser', async (userId) => {
        socket.userId = userId; // Guardamos el ID en el socket para validaciones futuras
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
        // "El Portero": Validación de permisos
        const userId = socket.userId;

        // Si la sala es un número, asumimos que es un Grupo de la BD
        if (!isNaN(room)) {
            if (!userId) {
                return socket.emit('error', 'No estás autenticado en el chat.');
            }
            try {
                const result = await pool.query(
                    'SELECT 1 FROM group_members WHERE user_id = $1 AND group_id = $2',
                    [userId, room]
                );

                if (result.rows.length === 0) {
                    console.log(`⛔ Acceso denegado: Usuario ${userId} intentó entrar a sala ${room}`);
                    return socket.emit('error', 'No tienes permiso para entrar a esta sala.');
                }
            } catch (err) {
                console.error('Error validando permisos de sala:', err);
                return;
            }
        }

        if (currentRoom) socket.leave(currentRoom);
        socket.join(room);
        currentRoom = room;
        console.log(`✅ Usuario ${userId || 'Anónimo'} (Socket ${socket.id}) se unió a la sala: ${room}`);
    });

    socket.on('sendMessage', async (data) => {
        try {
            const { text, userId, room } = data;
            await pool.query('INSERT INTO messages (content, user_id, group_id) VALUES ($1, $2, $3)', [text, userId, room]);
            io.to(room).emit('receiveMessage', data);
        } catch (err) { console.error('❌ Error al procesar mensaje:', err); }
    });

    socket.on('createGroup', async (groupData) => {
        const { name, members, creatorId } = groupData;
        try {
            const groupResult = await pool.query('INSERT INTO groups (name, creator_id, description) VALUES ($1, $2, $3) RETURNING *', [name, creatorId, `Grupo de ${members.length} miembros`]);
            const newGroup = groupResult.rows[0];
            for (const memberId of members) {
                await pool.query('INSERT INTO group_members (user_id, group_id) VALUES ($1, $2)', [memberId, newGroup.id]);
            }
            console.log(`✅ Grupo "${newGroup.name}" creado en la BD.`);
            const groupInfoForClient = { id: newGroup.id, name: newGroup.name, description: newGroup.description };
            members.forEach(memberId => {
                const memberSocketId = userSocketMap[memberId];
                if (memberSocketId) io.to(memberSocketId).emit('newGroupAdded', groupInfoForClient);
            });
        } catch (err) { console.error("Error al crear grupo en BD:", err); }
    });

    // --- Lógica de Videollamada (Señalización) ---
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

    // --- Desconexión ---
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

    // --- Lógica de Simulación de Partidos ---
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

// 8. INICIAR EL SERVIDOR
server.listen(PORT, () => {
    console.log(`🚀 Servidor escuchando en el puerto ${PORT}`);
});