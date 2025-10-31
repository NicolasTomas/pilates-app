const path = require('path');
const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017';
// Optional fallback URI (useful for local development if Atlas SRV fails due to TLS/OpenSSL issues)
const FALLBACK_MONGO_URI = process.env.FALLBACK_MONGO_URI || process.env.LOCAL_MONGO_URI || 'mongodb://localhost:27017';
const DB_NAME = process.env.DB_NAME || 'pilatesdb';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change';

// Configuración por defecto del gimnasio
const DEFAULT_GYM_CONFIG = {
    minCancellationHours: 24,
    creditExpirationDays: 30,
    autoCancelDueOverdueDays: 7,
    maxCredits: 10
};

let db;

async function connectDB() {
    const client = new MongoClient(MONGO_URI, { useUnifiedTopology: true });
    try {
        await client.connect();
        db = client.db(DB_NAME);
        console.log('Connected to MongoDB', MONGO_URI, DB_NAME);
    } catch (err) {
        // Print a concise warning by default (the raw OpenSSL stack is noisy on Windows);
        // if you need diagnostics, set DEBUG_MONGO=1 in the environment to see the full error.
        const primaryErrMsg = err && err.message ? err.message : String(err);
        if (process.env.DEBUG_MONGO) {
            console.error('Primary Mongo connection failed:', primaryErrMsg, err);
        } else {
            console.warn('Primary Mongo connection failed (TLS/SSL). Will attempt fallback if configured.');
            console.warn('To see the full error set DEBUG_MONGO=1 and restart the server.');
        }

        // If the primary URI is an Atlas SRV and we have a fallback, try it and give the developer guidance
        if (FALLBACK_MONGO_URI && FALLBACK_MONGO_URI !== MONGO_URI) {
            console.log(`Attempting fallback Mongo connection to ${FALLBACK_MONGO_URI}...`);
            try {
                const fallbackClient = new MongoClient(FALLBACK_MONGO_URI, { useUnifiedTopology: true });
                await fallbackClient.connect();
                db = fallbackClient.db(DB_NAME);
                console.log('Connected to MongoDB using fallback URI', FALLBACK_MONGO_URI, DB_NAME);
                return;
            } catch (err2) {
                console.error('Fallback Mongo connection also failed:', err2 && err2.message ? err2.message : err2);
                // fall through to final error handling below
            }
        }

        // Provide actionable hints for the developer when TLS/SSL errors occur with Atlas
        if (err && err.message && /SSL|tls|TLS|certificate|alert/i.test(err.message)) {
            console.error('\nDetected an SSL/TLS error when connecting to MongoDB Atlas. Common causes and fixes:');
            console.error('- Your Node/OpenSSL build may be incompatible with Atlas SRV TLS. Try upgrading Node or OpenSSL.');
            console.error("- For local development, set FALLBACK_MONGO_URI or LOCAL_MONGO_URI to 'mongodb://localhost:27017' and run a local mongod instance.");
            console.error('- Ensure your environment allows outbound TLS connections to Atlas (firewall, proxy, corporate network).');
            console.error('- If you intentionally want to use Atlas, try connecting from a machine with updated crypto libraries.');
        }

        throw err;
    }

    // Asegurar que existe la configuración del gimnasio
    const gym = await db.collection('gyms').findOne({});
    if (!gym) {
        await db.collection('gyms').insertOne({
            ...DEFAULT_GYM_CONFIG,
            createdAt: new Date()
        });
    }
}

function generateToken(user) {
    const payload = { id: user._id.toString(), role: user.role };
    if (user.dni) payload.dni = user.dni;
    if (user.email) payload.email = user.email;
    if (user.gymId) payload.gymId = user.gymId;
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });
}

async function getUserByEmail(email) {
    return db.collection('users').findOne({ email: email });
}

async function getUserByDni(dni) {
    return db.collection('users').findOne({ dni: dni });
}

app.post('/api/login', async (req, res) => {
    const { dni } = req.body;
    if (!dni) return res.status(400).json({ error: 'DNI es requerido' });
    try {
        const user = await getUserByDni(dni);
        if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });
        const token = generateToken(user);
        res.json({ token, role: user.role });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

// Admin login via email + password
app.post('/api/admin/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email y password son requeridos' });
    try {
        const user = await getUserByEmail(email);
        if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });
        // validar rol
        if (!['administrador', 'superusuario'].includes(user.role)) {
            return res.status(403).json({ error: 'No tiene permisos de administrador' });
        }
        if (!user.password) return res.status(401).json({ error: 'Usuario sin contraseña' });
        const ok = await bcrypt.compare(password, user.password);
        if (!ok) return res.status(401).json({ error: 'Credenciales incorrectas' });
        const token = generateToken(user);
        res.json({ token, role: user.role });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

app.get('/api/me', (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        res.json({ id: payload.id, role: payload.role, dni: payload.dni, gymId: payload.gymId });
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }
});

// Middleware para verificar token y rol admin/superusuario
function authMiddleware(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        if (!['administrador', 'superusuario'].includes(payload.role)) {
            return res.status(403).json({ error: 'No tienes permisos' });
        }
        // Attach user payload (including gymId if present)
        req.user = payload;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }
}

// Helper to extract payload from Authorization header for routes that don't use authMiddleware
function verifyToken(req) {
    const auth = req.headers.authorization;
    if (!auth) throw new Error('No autorizado');
    const parts = auth.split(' ');
    if (parts.length !== 2) throw new Error('Token mal formado');
    const token = parts[1];
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (err) {
        throw new Error('Token inválido');
    }
}

// CRUD Salones (rooms)
app.get('/api/rooms', authMiddleware, async (req, res) => {
    try {
        // Admins see only their gym rooms; superusuario sees all
        const q = {};
        if (req.user.role !== 'superusuario') q.gymId = req.user.gymId;
        const rooms = await db.collection('rooms').find(q).toArray();
        res.json(rooms);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al listar salones' });
    }
});

// List users (opcionalmente filtrar por rol y búsqueda)
app.get('/api/users', authMiddleware, async (req, res) => {
    try {
        const { role, search } = req.query;
        let q = {};

        // Filtro por rol
        if (role) {
            q.role = role;
        }

        // Si no es superusuario, limitar por gym
        if (req.user.role !== 'superusuario') {
            q.gymId = req.user.gymId;
        }

        // Búsqueda por nombre, apellido o DNI
        if (search) {
            const searchRegex = new RegExp(search, 'i');
            q.$or = [
                { name: searchRegex },
                { lastName: searchRegex },
                { dni: searchRegex }
            ];
        }

        const users = await db.collection('users')
            .find(q)
            .project({ password: 0 })
            .sort({ lastName: 1, name: 1 })
            .toArray();

        res.json(users);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al listar usuarios' });
    }
});

// Obtener clases de un alumno (solo el propio alumno o admin/superusuario)
app.get('/api/students/:id/classes', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }

    const { id } = req.params;
    // Permitir si es admin/superusuario
    if (!['administrador', 'superusuario'].includes(payload.role) && payload.id !== id) {
        return res.status(403).json({ error: 'No tienes permisos para ver estas clases' });
    }

    try {
        const studentObjectId = new ObjectId(id);
        // Filtrar por gymId si el payload contiene gymId (admins) o para proteger multi-tenancy
        const q = { students: studentObjectId };
        if (payload.gymId) q.gymId = payload.gymId;
        const classes = await db.collection('classes').find(q).toArray();
        const populated = await Promise.all(classes.map(async c => {
            const room = c.roomId ? await db.collection('rooms').findOne({ _id: new ObjectId(c.roomId) }) : null;
            const professor = c.professorId ? await db.collection('users').findOne({ _id: new ObjectId(c.professorId) }) : null;
            const studentsCount = Array.isArray(c.students) ? c.students.length : 0;
            const capacity = room ? room.capacity : 0;
            return Object.assign({}, c, { roomName: room ? room.name : null, professorName: professor ? professor.name : null, camillasFree: Math.max(0, capacity - studentsCount) });
        }));
        res.json(populated);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al obtener clases del alumno' });
    }
});

// Obtener datos de un alumno (propio) o admin/superusuario
app.get('/api/students/:id', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }
    const { id } = req.params;
    if (!['administrador', 'superusuario'].includes(payload.role) && payload.id !== id) {
        return res.status(403).json({ error: 'No tienes permisos para ver este alumno' });
    }
    try {
        const _id = new ObjectId(id);
        const q = { _id, role: 'alumno' };
        if (payload.gymId) q.gymId = payload.gymId;
        const student = await db.collection('users').findOne(q, { projection: { password: 0 } });
        if (!student) return res.status(404).json({ error: 'Alumno no encontrado' });
        res.json(student);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al obtener alumno' });
    }
});

// Listado de clases con capacidad (abierto a cualquier usuario autenticado)
app.get('/api/classes/open', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    try {
        jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }
    try {
        // limit to gym if token contains gymId
        let q = {};
        const payload = verifyToken(req);
        if (payload.gymId) q.gymId = payload.gymId;
        const classes = await db.collection('classes').find(q).toArray();
        const populated = await Promise.all(classes.map(async c => {
            const room = c.roomId ? await db.collection('rooms').findOne({ _id: new ObjectId(c.roomId) }) : null;
            const professor = c.professorId ? await db.collection('users').findOne({ _id: new ObjectId(c.professorId) }) : null;
            const studentsCount = Array.isArray(c.students) ? c.students.length : 0;
            const capacity = room ? room.capacity : 0;
            return Object.assign({}, c, { roomName: room ? room.name : null, professorName: professor ? professor.name : null, camillasFree: Math.max(0, capacity - studentsCount) });
        }));
        res.json(populated);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al listar clases abiertas' });
    }
});

// Config pública del gimnasio (sin auth)
app.get('/api/gym/config/public', async (req, res) => {
    try {
        const config = await db.collection('gyms').findOne({});
        res.json(config || DEFAULT_GYM_CONFIG);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al obtener configuración pública' });
    }
});

// Obtener instancias de clase de un alumno (solo el propio alumno o admin/superusuario)
app.get('/api/students/:id/class-instances', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }

    const { id } = req.params;
    if (!['administrador', 'superusuario'].includes(payload.role) && payload.id !== id) {
        return res.status(403).json({ error: 'No tienes permisos para ver estas clases' });
    }

    try {
        const studentObjectId = new ObjectId(id);
        const now = new Date();

        // Determine upper bound: from now until (dueDate + autoCancelDueOverdueDays)
        // If the student has a dueDate, we limit instances to that window so the
        // UI shows classes until the grace period after quota expiration.
        let upperLimit = null;
        try {
            const userDoc = await db.collection('users').findOne({ _id: studentObjectId });
            const gym = await db.collection('gyms').findOne({}) || DEFAULT_GYM_CONFIG;
            const extraDays = (gym && gym.autoCancelDueOverdueDays) ? gym.autoCancelDueOverdueDays : DEFAULT_GYM_CONFIG.autoCancelDueOverdueDays;
            if (userDoc && userDoc.dueDate) {
                const venc = new Date(userDoc.dueDate);
                venc.setDate(venc.getDate() + Number(extraDays || 0));
                upperLimit = venc;
            }
        } catch (e) {
            console.warn('Warning: failed to compute dueDate upper limit for student class instances', e);
            upperLimit = null;
        }

        // Obtener instancias futuras donde el alumno está inscrito (acotadas por upperLimit si existe)
        const q = {
            students: studentObjectId,
            dateTime: { $gte: now },
            status: { $ne: 'cancelled' }
        };
        if (upperLimit) q.dateTime.$lte = upperLimit;
        if (payload.gymId) q.gymId = payload.gymId;
        const instances = await db.collection('classInstances')
            .find(q)
            .sort({ dateTime: 1 })
            .toArray();

        const populated = await Promise.all(instances.map(async inst => {
            const room = inst.roomId ? await db.collection('rooms').findOne({ _id: new ObjectId(inst.roomId) }) : null;
            const professor = inst.professorId ? await db.collection('users').findOne({ _id: new ObjectId(inst.professorId) }) : null;
            const studentsCount = Array.isArray(inst.students) ? inst.students.length : 0;
            const capacity = room ? room.capacity : 0;
            return {
                ...inst,
                roomName: room ? room.name : null,
                professorName: professor ? professor.name : null,
                camillasFree: Math.max(0, capacity - studentsCount)
            };
        }));

        // If caller requests debug info, include the computed upperLimit for visibility
        if (req.query && req.query.debug === '1') {
            return res.json({ upperLimit: upperLimit ? upperLimit.toISOString() : null, instances: populated });
        }

        res.json(populated);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al obtener instancias del alumno' });
    }
});

// Listar instancias disponibles para recuperar (abierto a cualquier usuario autenticado)
app.get('/api/class-instances/available', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    try {
        jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }

    try {
        const now = new Date();
        const payload = verifyToken(req);
        const q = { dateTime: { $gte: now }, status: 'scheduled' };
        if (payload.gymId) q.gymId = payload.gymId;
        const instances = await db.collection('classInstances')
            .find(q)
            .sort({ dateTime: 1 })
            .toArray();

        const populated = await Promise.all(instances.map(async inst => {
            const room = inst.roomId ? await db.collection('rooms').findOne({ _id: new ObjectId(inst.roomId) }) : null;
            const professor = inst.professorId ? await db.collection('users').findOne({ _id: new ObjectId(inst.professorId) }) : null;
            const studentsCount = Array.isArray(inst.students) ? inst.students.length : 0;
            const capacity = room ? room.capacity : 0;
            const camillasFree = Math.max(0, capacity - studentsCount);

            return {
                ...inst,
                roomName: room ? room.name : null,
                professorName: professor ? professor.name : null,
                camillasFree
            };
        }));

        // Solo devolver las que tienen capacidad
        res.json(populated.filter(p => p.camillasFree > 0));
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al listar instancias disponibles' });
    }
});

// Cancelar instancia para un alumno (genera un ticket de crédito)
app.post('/api/students/:id/cancel-instance/:instanceId', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }

    const { id, instanceId } = req.params;
    if (!['administrador', 'superusuario'].includes(payload.role) && payload.id !== id) {
        return res.status(403).json({ error: 'No tienes permisos para cancelar esta clase' });
    }

    try {
        const studentObjectId = new ObjectId(id);
        const instanceObjectId = new ObjectId(instanceId);

        const instance = await db.collection('classInstances').findOne({ _id: instanceObjectId });
        if (!instance) return res.status(404).json({ error: 'Instancia no encontrada' });

        // Ensure the instance belongs to the same gym as the requester (unless superusuario)
        if (payload.role !== 'superusuario' && instance.gymId && instance.gymId !== payload.gymId) {
            return res.status(403).json({ error: 'No tenés permisos para recuperar esta instancia' });
        }

        // Ensure the instance belongs to the same gym as the requester (unless superusuario)
        if (payload.role !== 'superusuario' && instance.gymId && instance.gymId !== payload.gymId) {
            return res.status(403).json({ error: 'No tenés permisos para cancelar esta instancia' });
        }

        if (!instance.students || !instance.students.some(sid => sid.toString() === id)) {
            return res.status(404).json({ error: 'El estudiante no está inscrito en esta instancia' });
        }

        // Obtener configuración del gimnasio correspondiente (si existe gymId en instancia o en payload)
        let gym = await db.collection('gyms').findOne({});
        try {
            const payload = payload || jwt.verify(token, JWT_SECRET);
            if (payload && payload.gymId) {
                const g = await db.collection('gyms').findOne({ gymId: payload.gymId });
                if (g) gym = g;
            }
        } catch (e) { }
        const now = new Date();
        const diffHours = (new Date(instance.dateTime) - now) / 36e5;

        let generateTicket = diffHours >= gym.minCancellationHours;

        // Remover estudiante de la instancia
        await db.collection('classInstances').updateOne(
            { _id: instanceObjectId },
            { $pull: { students: studentObjectId }, $set: { updatedAt: new Date() } }
        );

        let ticket = null;
        if (generateTicket) {
            const creditDays = gym.creditExpirationDays || DEFAULT_GYM_CONFIG.creditExpirationDays;
            ticket = {
                id: new ObjectId().toString(),
                instanceId: instanceId,
                instanceSnapshot: {
                    dateTime: instance.dateTime,
                    duration: instance.duration,
                    roomId: instance.roomId,
                    professorId: instance.professorId
                },
                createdAt: new Date(),
                expiresAt: new Date(Date.now() + creditDays * 24 * 60 * 60 * 1000),
                status: 'active'
            };

            await db.collection('users').updateOne(
                { _id: studentObjectId },
                { $push: { tickets: ticket }, $set: { updatedAt: new Date() } }
            );
        }

        res.json({ ticket, message: generateTicket ? 'Ticket generado' : 'Cancelación sin ticket (menos de ' + gym.minCancellationHours + 'hs)' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al cancelar instancia' });
    }
});

// Create a ticket for a student (force-create, used by client when backend didn't
// generate one automatically). This endpoint requires Authorization and can be
// called by the student themself or by admin/superusuario.
app.post('/api/students/:id/create-ticket', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }

    const { id } = req.params;
    const { classId, instanceId } = req.body || {};

    // Permission check
    if (!['administrador', 'superusuario'].includes(payload.role) && payload.id !== id) {
        return res.status(403).json({ error: 'No tienes permisos para crear ticket' });
    }

    try {
        const studentObjectId = new ObjectId(id);
        const gym = await db.collection('gyms').findOne({}) || DEFAULT_GYM_CONFIG;
        const creditDays = gym.creditExpirationDays || DEFAULT_GYM_CONFIG.creditExpirationDays;

        const ticket = {
            id: new ObjectId().toString(),
            classId: classId || null,
            instanceId: instanceId || null,
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + creditDays * 24 * 60 * 60 * 1000),
            status: 'active'
        };

        await db.collection('users').updateOne(
            { _id: studentObjectId },
            { $push: { tickets: ticket }, $set: { updatedAt: new Date() } }
        );

        res.json({ ticket });
    } catch (err) {
        console.error('Error creating ticket:', err);
        res.status(500).json({ error: 'Error al crear ticket' });
    }
});

// Recuperar una instancia usando un ticket
app.post('/api/students/:id/recover-instance/:instanceId', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }

    const { id, instanceId } = req.params;
    const { ticketId } = req.body;
    if (!ticketId) return res.status(400).json({ error: 'ticketId es requerido' });

    if (!['administrador', 'superusuario'].includes(payload.role) && payload.id !== id) {
        return res.status(403).json({ error: 'No tienes permisos para recuperar esta clase' });
    }

    try {
        const studentObjectId = new ObjectId(id);
        const instanceObjectId = new ObjectId(instanceId);

        const user = await db.collection('users').findOne({ _id: studentObjectId });
        if (!user) return res.status(404).json({ error: 'Alumno no encontrado' });

        const ticket = (user.tickets || []).find(t => t.id === ticketId);
        if (!ticket) return res.status(404).json({ error: 'Ticket no encontrado' });
        if (ticket.status !== 'active') return res.status(400).json({ error: 'Ticket ya fue usado o no está activo' });
        if (new Date(ticket.expiresAt) < new Date()) return res.status(400).json({ error: 'Ticket expirado' });

        const instance = await db.collection('classInstances').findOne({ _id: instanceObjectId });
        if (!instance) return res.status(404).json({ error: 'Instancia no encontrada' });

        const room = instance.roomId ? await db.collection('rooms').findOne({ _id: new ObjectId(instance.roomId) }) : null;
        const studentsCount = Array.isArray(instance.students) ? instance.students.length : 0;
        const capacity = room ? room.capacity : 0;
        if (studentsCount >= capacity) {
            return res.status(400).json({ error: 'La clase está llena' });
        }

        // Inscribir al alumno en la instancia
        await db.collection('classInstances').updateOne(
            { _id: instanceObjectId },
            { $push: { students: studentObjectId }, $set: { updatedAt: new Date() } }
        );

        // Marcar ticket como usado
        await db.collection('users').updateOne(
            { _id: studentObjectId, 'tickets.id': ticketId },
            { $set: { 'tickets.$.status': 'used', 'tickets.$.usedAt': new Date(), updatedAt: new Date() } }
        );

        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al recuperar instancia con ticket' });
    }
});

// CRUD Alumnos
app.post('/api/students', authMiddleware, async (req, res) => {
    const {
        dni, name, lastName, phone, emergencyContact,
        membershipType, dueDate, classIds = []
    } = req.body;

    // Validar campos requeridos
    if (!dni || !name || !lastName) {
        return res.status(400).json({ error: 'DNI, nombre y apellido son requeridos' });
    }

    try {
        // Verificar DNI duplicado
        const exists = await db.collection('users').findOne({ dni });
        if (exists) {
            return res.status(409).json({ error: 'Ya existe un usuario con ese DNI' });
        }

        // Si se especifican clases, validar capacidad
        if (classIds.length > 0) {
            const classes = await db.collection('classes').find({
                _id: { $in: classIds.map(id => new ObjectId(id)) }
            }).toArray();

            // Verificar que existan todas las clases
            if (classes.length !== classIds.length) {
                return res.status(400).json({ error: 'Una o más clases no existen' });
            }

            // Verificar capacidad en cada clase
            for (const clase of classes) {
                const room = await db.collection('rooms').findOne({ _id: new ObjectId(clase.roomId) });
                if (!room) continue;

                const studentsCount = clase.students ? clase.students.length : 0;
                if (studentsCount >= room.capacity) {
                    return res.status(400).json({
                        error: `La clase de ${clase.days.join(', ')} ${clase.start} está llena`
                    });
                }
            }
        }

        // Crear alumno
        const student = {
            dni,
            name,
            lastName,
            phone,
            emergencyContact,
            membershipType,
            dueDate: dueDate ? new Date(dueDate) : null,
            role: 'alumno',
            gymId: req.user.gymId || null,
            createdAt: new Date()
        };

        const result = await db.collection('users').insertOne(student);
        const studentId = result.insertedId;

        // Inscribir en las clases especificadas
        if (classIds.length > 0) {
            await db.collection('classes').updateMany(
                { _id: { $in: classIds.map(id => new ObjectId(id)) } },
                { $push: { students: studentId } }
            );
        }

        // Also add the student to future generated instances of those classes
        if (classIds.length > 0) {
            const now = new Date();
            await db.collection('classInstances').updateMany(
                { classId: { $in: classIds.map(id => new ObjectId(id)) }, dateTime: { $gte: now }, status: 'scheduled' },
                { $push: { students: studentId }, $set: { updatedAt: new Date() } }
            );
        }

        res.json({ id: studentId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al crear alumno' });
    }
});

app.put('/api/students/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const {
        dni, name, lastName, phone, emergencyContact,
        membershipType, dueDate, classIds = []
    } = req.body;

    if (!dni || !name || !lastName) {
        return res.status(400).json({ error: 'DNI, nombre y apellido son requeridos' });
    }

    try {
        const _id = new ObjectId(id);

        // Verificar que el alumno exista
        const currentStudent = await db.collection('users').findOne({ _id, role: 'alumno' });
        if (!currentStudent) {
            return res.status(404).json({ error: 'Alumno no encontrado' });
        }

        // Verificar DNI duplicado (excepto si es el mismo alumno)
        const exists = await db.collection('users').findOne({ dni, _id: { $ne: _id } });
        if (exists) {
            return res.status(409).json({ error: 'Ya existe otro usuario con ese DNI' });
        }

        // Obtener clases actuales del alumno
        const currentClasses = await db.collection('classes')
            .find({ students: _id })
            .toArray();

        const currentClassIds = currentClasses.map(c => c._id.toString());
        const classesToAdd = classIds.filter(id => !currentClassIds.includes(id));
        const classesToRemove = currentClassIds.filter(id => !classIds.includes(id));

        // Validar capacidad en las nuevas clases
        if (classesToAdd.length > 0) {
            const newClasses = await db.collection('classes')
                .find({ _id: { $in: classesToAdd.map(id => new ObjectId(id)) } })
                .toArray();

            for (const clase of newClasses) {
                const room = await db.collection('rooms').findOne({ _id: new ObjectId(clase.roomId) });
                if (!room) continue;

                const studentsCount = clase.students ? clase.students.length : 0;
                if (studentsCount >= room.capacity) {
                    return res.status(400).json({
                        error: `La clase de ${clase.days.join(', ')} ${clase.start} está llena`
                    });
                }
            }
        }

        // Actualizar datos del alumno
        await db.collection('users').updateOne(
            { _id },
            {
                $set: {
                    dni,
                    name,
                    lastName,
                    phone,
                    emergencyContact,
                    membershipType,
                    dueDate: dueDate ? new Date(dueDate) : null,
                    updatedAt: new Date()
                }
            }
        );

        // Si se actualizó la cuota (dueDate) queremos asegurar que las instancias
        // de clases se generen hasta el nuevo vencimiento + grace (autoCancelDueOverdueDays)
        // y que el alumno esté registrado en esas instancias para que la UI muestre
        // todas las clases hasta el vencimiento inmediatamente.
        if (dueDate) {
            try {
                // Calcular upperLimit = dueDate + gym.autoCancelDueOverdueDays
                const gym = await db.collection('gyms').findOne({}) || DEFAULT_GYM_CONFIG;
                const extraDays = (gym && gym.autoCancelDueOverdueDays) ? Number(gym.autoCancelDueOverdueDays) : DEFAULT_GYM_CONFIG.autoCancelDueOverdueDays;
                const venc = new Date(dueDate);
                const upperLimit = new Date(venc);
                upperLimit.setDate(upperLimit.getDate() + (extraDays || 0));

                // Calcular días a generar desde hoy (start of day)
                const today = new Date();
                today.setHours(0, 0, 0, 0);
                let daysAhead = Math.ceil((upperLimit - today) / 864e5);
                if (daysAhead < 0) daysAhead = 0;
                // Limitar por seguridad (no generar más de 90 días de golpe)
                const MAX_GENERATE_DAYS = 90;
                if (daysAhead > MAX_GENERATE_DAYS) daysAhead = MAX_GENERATE_DAYS;

                if (daysAhead > 0) {
                    // Generar instancias globalmente (la función ya itera por todas las clases)
                    await generateClassInstances(daysAhead);

                    // Obtener las clases en las que el alumno está inscrito ahora
                    const enrolledClasses = await db.collection('classes').find({ students: _id }).project({ _id: 1 }).toArray();
                    const enrolledClassIds = enrolledClasses.map(c => c._id);

                    if (enrolledClassIds.length > 0) {
                        // Añadir al alumno a las instancias futuras (hasta upperLimit) de sus clases
                        await db.collection('classInstances').updateMany(
                            {
                                classId: { $in: enrolledClassIds },
                                dateTime: { $gte: new Date(), $lte: upperLimit },
                                status: 'scheduled'
                            },
                            { $addToSet: { students: _id }, $set: { updatedAt: new Date() } }
                        );
                    }
                }
            } catch (e) {
                console.warn('Warning: failed to generate/sync classInstances after dueDate update for student', id, e);
            }
        }

        // Actualizar inscripciones a clases
        if (classesToAdd.length > 0) {
            await db.collection('classes').updateMany(
                { _id: { $in: classesToAdd.map(id => new ObjectId(id)) } },
                { $push: { students: _id } }
            );
            // Also add student to future instances of added classes
            const now = new Date();
            await db.collection('classInstances').updateMany(
                { classId: { $in: classesToAdd.map(id => new ObjectId(id)) }, dateTime: { $gte: now }, status: 'scheduled' },
                { $push: { students: _id }, $set: { updatedAt: new Date() } }
            );
        }

        if (classesToRemove.length > 0) {
            await db.collection('classes').updateMany(
                { _id: { $in: classesToRemove.map(id => new ObjectId(id)) } },
                { $pull: { students: _id } }
            );
            // Also remove student from future instances of removed classes
            const now2 = new Date();
            await db.collection('classInstances').updateMany(
                { classId: { $in: classesToRemove.map(id => new ObjectId(id)) }, dateTime: { $gte: now2 }, status: 'scheduled' },
                { $pull: { students: _id }, $set: { updatedAt: new Date() } }
            );
        }

        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al actualizar alumno' });
    }
});

app.delete('/api/students/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        const _id = new ObjectId(id);

        // Verificar que el alumno exista
        const student = await db.collection('users').findOne({ _id, role: 'alumno' });
        if (!student) {
            return res.status(404).json({ error: 'Alumno no encontrado' });
        }

        // Verificar que el alumno pertenezca al mismo gym que el admin (salvo superusuario)
        if (req.user.role !== 'superusuario' && student.gymId && student.gymId !== req.user.gymId) {
            return res.status(403).json({ error: 'No tenés permisos para eliminar este alumno' });
        }

        // Eliminar alumno de todas las clases
        await db.collection('classes').updateMany(
            { students: _id },
            { $pull: { students: _id } }
        );

        // Eliminar alumno
        await db.collection('users').deleteOne({ _id });

        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al eliminar alumno' });
    }
});

app.post('/api/rooms', authMiddleware, async (req, res) => {
    const { name, capacity } = req.body;
    if (!name || !capacity) return res.status(400).json({ error: 'Nombre y capacidad son requeridos' });
    try {
        // rooms are per-gym
        const q = { name, gymId: req.user.gymId };
        const exists = await db.collection('rooms').findOne(q);
        if (exists) return res.status(409).json({ error: 'Ya existe un salón con ese nombre en este gimnasio' });
        const result = await db.collection('rooms').insertOne({ name, capacity: Number(capacity), gymId: req.user.gymId });
        res.json({ id: result.insertedId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al crear salón' });
    }
});

app.put('/api/rooms/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const { name, capacity } = req.body;
    if (!name || !capacity) return res.status(400).json({ error: 'Nombre y capacidad son requeridos' });
    try {
        const { ObjectId } = require('mongodb');
        const _id = new ObjectId(id);
        // Ensure room belongs to gym (unless superusuario)
        const room = await db.collection('rooms').findOne({ _id });
        if (!room) return res.status(404).json({ error: 'Salón no encontrado' });
        if (req.user.role !== 'superusuario' && room.gymId !== req.user.gymId) return res.status(403).json({ error: 'No tenés permisos para modificar este salón' });
        await db.collection('rooms').updateOne({ _id }, { $set: { name, capacity: Number(capacity) } });
        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al actualizar salón' });
    }
});

app.delete('/api/rooms/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        const { ObjectId } = require('mongodb');
        const _id = new ObjectId(id);
        const room = await db.collection('rooms').findOne({ _id });
        if (!room) return res.status(404).json({ error: 'Salón no encontrado' });
        if (req.user.role !== 'superusuario' && room.gymId !== req.user.gymId) return res.status(403).json({ error: 'No tenés permisos para eliminar este salón' });
        await db.collection('rooms').deleteOne({ _id });
        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al eliminar salón' });
    }
});

// CRUD Clases (classes)

// Validaciones
function validateTime(time) {
    return /^([0-1][0-9]|2[0-3]):[0-5][0-9]$/.test(time);
}

function validateDuration(duration) {
    return Number.isInteger(duration) && duration > 0 && duration <= 180;
}

// Calcula camillas libres y valida capacidad
async function validateClassCapacity(roomId, classId = null) {
    const room = await db.collection('rooms').findOne({ _id: new ObjectId(roomId) });
    if (!room) throw new Error('Salón no encontrado');
    return { capacity: room.capacity, name: room.name };
}

app.get('/api/classes', authMiddleware, async (req, res) => {
    try {
        const q = {};
        if (req.user.role !== 'superusuario') q.gymId = req.user.gymId;
        const classes = await db.collection('classes').find(q).toArray();
        // populate room and professor and calculate camillas libres
        const populated = await Promise.all(classes.map(async c => {
            const room = c.roomId ? await db.collection('rooms').findOne({ _id: new ObjectId(c.roomId) }) : null;
            const professor = c.professorId ? await db.collection('users').findOne({ _id: new ObjectId(c.professorId) }) : null;
            const studentsCount = Array.isArray(c.students) ? c.students.length : 0;
            const capacity = room ? room.capacity : 0;
            return Object.assign({}, c, { roomName: room ? room.name : null, professorName: professor ? professor.name : null, camillasFree: Math.max(0, capacity - studentsCount) });
        }));
        res.json(populated);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al listar clases' });
    }
});

app.post('/api/classes', authMiddleware, async (req, res) => {
    const { days, start, duration, roomId, professorId } = req.body;
    if (!days || !Array.isArray(days) || !start || !duration || !roomId)
        return res.status(400).json({ error: 'Faltan datos requeridos' });

    // Validar formato de hora y duración
    if (!validateTime(start))
        return res.status(400).json({ error: 'Formato de hora inválido. Use HH:MM (24h)' });
    if (!validateDuration(Number(duration)))
        return res.status(400).json({ error: 'Duración inválida. Debe estar entre 1 y 180 minutos' });

    try {
        // Validar capacidad del salón y que exista
        const room = await validateClassCapacity(roomId);
        if (!room) return res.status(404).json({ error: 'Salón no encontrado' });

        // Verificar que el salón pertenece al mismo gym que el admin
        const roomDoc = await db.collection('rooms').findOne({ _id: new ObjectId(roomId) });
        if (req.user.role !== 'superusuario' && roomDoc && roomDoc.gymId !== req.user.gymId) {
            return res.status(403).json({ error: 'No tenés permisos para usar ese salón' });
        }

        // Validar duplicados: mismo room, mismo start y días intersectan
        const conflict = await db.collection('classes').findOne({
            roomId: roomId,
            start: start,
            days: { $in: days },
            gymId: req.user.gymId
        });
        if (conflict)
            return res.status(409).json({ error: 'Ya existe una clase en ese salón con el mismo horario y días' });

        // Validar que el profesor exista si se proporciona
        if (professorId) {
            const professor = await db.collection('users').findOne({
                _id: new ObjectId(professorId),
                role: 'profesor'
            });
            if (!professor)
                return res.status(404).json({ error: 'Profesor no encontrado' });
        }

        const doc = {
            days,
            start,
            duration: Number(duration),
            roomId,
            professorId: professorId || null,
            gymId: req.user.gymId,
            students: [],
            createdAt: new Date()
        };

        const result = await db.collection('classes').insertOne(doc);
        res.json({ id: result.insertedId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al crear clase' });
    }
});

app.put('/api/classes/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const { days, start, duration, roomId, professorId } = req.body;
    if (!days || !Array.isArray(days) || !start || !duration || !roomId)
        return res.status(400).json({ error: 'Faltan datos requeridos' });

    // Validar formato de hora y duración
    if (!validateTime(start))
        return res.status(400).json({ error: 'Formato de hora inválido. Use HH:MM (24h)' });
    if (!validateDuration(Number(duration)))
        return res.status(400).json({ error: 'Duración inválida. Debe estar entre 1 y 180 minutos' });

    try {
        const _id = new ObjectId(id);

        // Validar que la clase exista
        const existingClass = await db.collection('classes').findOne({ _id });
        if (!existingClass)
            return res.status(404).json({ error: 'Clase no encontrada' });

        // Validar capacidad del salón y que exista
        const room = await validateClassCapacity(roomId);
        if (!room)
            return res.status(404).json({ error: 'Salón no encontrado' });

        // Ensure the room belongs to the same gym as the class (unless superusuario)
        const roomDoc = await db.collection('rooms').findOne({ _id: new ObjectId(roomId) });
        if (req.user.role !== 'superusuario' && roomDoc && roomDoc.gymId !== existingClass.gymId) {
            return res.status(403).json({ error: 'No tenés permisos para usar ese salón' });
        }

        // Si hay estudiantes inscritos, validar que la capacidad del nuevo salón sea suficiente
        if (existingClass.students && existingClass.students.length > room.capacity) {
            return res.status(400).json({
                error: `No se puede cambiar al salón ${room.name} porque tiene ${existingClass.students.length} estudiantes y solo tiene capacidad para ${room.capacity}`
            });
        }

        // Verificar conflicto con otras clases (excluyendo esta)
        const conflict = await db.collection('classes').findOne({
            _id: { $ne: _id },
            roomId: roomId,
            start: start,
            days: { $in: days },
            gymId: existingClass.gymId
        });
        if (conflict)
            return res.status(409).json({ error: 'Conflicto con otra clase en ese salón' });

        // Validar que el profesor exista si se proporciona
        if (professorId) {
            const professor = await db.collection('users').findOne({
                _id: new ObjectId(professorId),
                role: 'profesor'
            });
            if (!professor)
                return res.status(404).json({ error: 'Profesor no encontrado' });
        }

        await db.collection('classes').updateOne(
            { _id },
            {
                $set: {
                    days,
                    start,
                    duration: Number(duration),
                    roomId,
                    professorId: professorId || null,
                    updatedAt: new Date()
                }
            }
        );
        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al actualizar clase' });
    }
});

app.delete('/api/classes/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        const _id = new ObjectId(id);
        const cls = await db.collection('classes').findOne({ _id });
        if (!cls) return res.status(404).json({ error: 'Clase no encontrada' });
        if (req.user.role !== 'superusuario' && cls.gymId !== req.user.gymId) return res.status(403).json({ error: 'No tenés permisos para eliminar esta clase' });
        await db.collection('classes').deleteOne({ _id });
        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al eliminar clase' });
    }
});

// Endpoints para gestión de estudiantes en clases

// Inscribir estudiante a una clase
app.post('/api/classes/:id/students', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const { studentId } = req.body;

    if (!studentId)
        return res.status(400).json({ error: 'ID del estudiante es requerido' });

    try {
        const _id = new ObjectId(id);
        const studentObjectId = new ObjectId(studentId);

        // Validar que la clase exista
        const classDoc = await db.collection('classes').findOne({ _id });
        if (!classDoc)
            return res.status(404).json({ error: 'Clase no encontrada' });

        // Validar que el estudiante exista y sea un estudiante
        const student = await db.collection('users').findOne({
            _id: studentObjectId,
            role: 'alumno'
        });
        if (!student)
            return res.status(404).json({ error: 'Estudiante no encontrado' });

        // Validar que el estudiante no esté ya inscrito
        if (classDoc.students && classDoc.students.some(id => id.toString() === studentId)) {
            return res.status(409).json({ error: 'El estudiante ya está inscrito en esta clase' });
        }

        // Validar capacidad del salón
        const room = await validateClassCapacity(classDoc.roomId);
        const currentStudents = classDoc.students ? classDoc.students.length : 0;
        if (currentStudents >= room.capacity) {
            return res.status(400).json({ error: 'La clase está llena' });
        }

        // Inscribir al estudiante
        await db.collection('classes').updateOne(
            { _id },
            {
                $push: { students: studentObjectId },
                $set: { updatedAt: new Date() }
            }
        );

        // Also add the student to future scheduled instances of this class
        try {
            const now = new Date();
            await db.collection('classInstances').updateMany(
                { classId: _id, dateTime: { $gte: now }, status: 'scheduled' },
                { $addToSet: { students: studentObjectId }, $set: { updatedAt: new Date() } }
            );
        } catch (e) {
            console.warn('Warning: failed to sync student into classInstances', e);
        }

        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al inscribir estudiante' });
    }
});

// CRUD Profesores
app.post('/api/professors', authMiddleware, async (req, res) => {
    const { dni, name, lastName, phone } = req.body;

    if (!dni || !name || !lastName) {
        return res.status(400).json({ error: 'DNI, nombre y apellido son requeridos' });
    }

    try {
        // Verificar DNI duplicado
        const exists = await db.collection('users').findOne({ dni });
        if (exists) {
            return res.status(409).json({ error: 'Ya existe un usuario con ese DNI' });
        }

        const professor = {
            dni,
            name,
            lastName,
            phone,
            role: 'profesor',
            gymId: req.user.gymId || null,
            createdAt: new Date()
        };

        const result = await db.collection('users').insertOne(professor);
        res.json({ id: result.insertedId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al crear profesor' });
    }
});

// Generar instancias de clases (llamar periódicamente o bajo demanda)
async function generateClassInstances(daysAhead = 30) {
    try {
        // Generate instances for all classes (including legacy ones without gymId)
        const classes = await db.collection('classes').find({}).toArray();
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        // Use unaccented day names to avoid mismatches (some parts of the UI use "miercoles" without accent)
        const daysNames = ['domingo', 'lunes', 'martes', 'miercoles', 'jueves', 'viernes', 'sabado'];

        // helper to strip accents and normalize
        const strip = (s = '') => s.toString().normalize('NFD').replace(/\p{Diacritic}/gu, '').toLowerCase();

        for (const clase of classes) {
            for (let dayOffset = 0; dayOffset < daysAhead; dayOffset++) {
                const targetDate = new Date(today);
                targetDate.setDate(today.getDate() + dayOffset);
                const dayName = daysNames[targetDate.getDay()];

                // Normalize clase.days entries and compare without accents
                const claseDaysNormalized = Array.isArray(clase.days) ? clase.days.map(d => strip(d)) : [];
                if (!claseDaysNormalized.includes(strip(dayName))) continue;

                // Parsear hora de inicio
                const [hours, minutes] = clase.start.split(':').map(Number);
                const instanceDateTime = new Date(targetDate);
                instanceDateTime.setHours(hours, minutes, 0, 0);

                // Verificar si ya existe esta instancia
                const exists = await db.collection('classInstances').findOne({
                    classId: clase._id,
                    dateTime: instanceDateTime
                });

                if (!exists) {
                    // Initialize instance students with currently enrolled students in the class
                    const initialStudents = Array.isArray(clase.students) ? clase.students : [];
                    await db.collection('classInstances').insertOne({
                        classId: clase._id,
                        dateTime: instanceDateTime,
                        duration: clase.duration,
                        roomId: clase.roomId,
                        professorId: clase.professorId,
                        students: initialStudents,
                        status: 'scheduled',
                        createdAt: new Date(),
                        gymId: clase.gymId || null
                    });
                }
            }
        }
    } catch (err) {
        console.error('Error generando instancias:', err);
    }
}

// Configuración del gimnasio
app.get('/api/gym/config', authMiddleware, async (req, res) => {
    try {
        // If superusuario may request specific gymId via query
        let gymId = req.user.gymId;
        if (req.user.role === 'superusuario' && req.query.gymId) gymId = req.query.gymId;
        const config = gymId ? await db.collection('gyms').findOne({ gymId }) : await db.collection('gyms').findOne({});
        res.json(config || DEFAULT_GYM_CONFIG);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al obtener configuración' });
    }
});

app.put('/api/gym/config', authMiddleware, async (req, res) => {
    const {
        minCancellationHours,
        creditExpirationDays,
        autoCancelDueOverdueDays,
        maxCredits
    } = req.body;

    // Validar que los campos sean enteros y respeten límites aceptables.
    // minCancellationHours and creditExpirationDays must be > 0.
    // autoCancelDueOverdueDays and maxCredits may be >= 0.
    if (!Number.isInteger(minCancellationHours) || minCancellationHours <= 0) {
        return res.status(400).json({ error: 'minCancellationHours debe ser un número entero positivo' });
    }
    if (!Number.isInteger(creditExpirationDays) || creditExpirationDays <= 0) {
        return res.status(400).json({ error: 'creditExpirationDays debe ser un número entero positivo' });
    }
    if (!Number.isInteger(autoCancelDueOverdueDays) || autoCancelDueOverdueDays < 0) {
        return res.status(400).json({ error: 'autoCancelDueOverdueDays debe ser un número entero mayor o igual a 0' });
    }
    if (!Number.isInteger(maxCredits) || maxCredits < 0) {
        return res.status(400).json({ error: 'maxCredits debe ser un número entero mayor o igual a 0' });
    }

    try {
        // Update the gym config for the admin's gym (or specified gym if superusuario)
        let gymId = req.user.gymId;
        if (req.user.role === 'superusuario' && req.query.gymId) gymId = req.query.gymId;
        if (gymId) {
            const gym = await db.collection('gyms').findOne({ gymId });
            if (gym) {
                await db.collection('gyms').updateOne(
                    { _id: gym._id },
                    { $set: { ...fields, updatedAt: new Date() } }
                );
            } else {
                await db.collection('gyms').insertOne({ gymId, ...fields, createdAt: new Date() });
            }
        } else {
            // fallback to single global gym doc
            const gym = await db.collection('gyms').findOne({});
            if (gym) {
                await db.collection('gyms').updateOne(
                    { _id: gym._id },
                    { $set: { ...fields, updatedAt: new Date() } }
                );
            } else {
                await db.collection('gyms').insertOne({ ...fields, createdAt: new Date() });
            }
        }

        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al actualizar configuración' });
    }
});

app.delete('/api/professors/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        const _id = new ObjectId(id);

        // Verificar que el profesor exista
        const professor = await db.collection('users').findOne({ _id, role: 'profesor' });
        if (!professor) {
            return res.status(404).json({ error: 'Profesor no encontrado' });
        }

        // Verificar si está asignado a clases (solo en su gym)
        const classQuery = { professorId: _id };
        if (req.user.role !== 'superusuario') classQuery.gymId = req.user.gymId;
        const assignedClasses = await db.collection('classes')
            .find(classQuery)
            .toArray();

        if (assignedClasses.length > 0) {
            return res.status(400).json({
                error: 'No se puede eliminar el profesor porque está asignado a una o más clases'
            });
        }

        // Verificar que el profesor pertenece al mismo gym (salvo superusuario)
        if (req.user.role !== 'superusuario' && professor.gymId && professor.gymId !== req.user.gymId) {
            return res.status(403).json({ error: 'No tenés permisos para eliminar este profesor' });
        }

        // Eliminar profesor
        await db.collection('users').deleteOne({ _id });

        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al eliminar profesor' });
    }
});

// Dar de baja estudiante de una clase
app.delete('/api/classes/:id/students/:studentId', authMiddleware, async (req, res) => {
    const { id, studentId } = req.params;

    try {
        const _id = new ObjectId(id);
        const studentObjectId = new ObjectId(studentId);

        // Validar que la clase exista
        const classDoc = await db.collection('classes').findOne({ _id });
        if (!classDoc)
            return res.status(404).json({ error: 'Clase no encontrada' });

        // Verificar que la clase pertenece al mismo gym que el admin
        if (req.user.role !== 'superusuario' && classDoc.gymId !== req.user.gymId) {
            return res.status(403).json({ error: 'No tenés permisos para inscribir estudiantes en esta clase' });
        }

        // Validar que el estudiante esté inscrito
        if (!classDoc.students || !classDoc.students.some(id => id.toString() === studentId)) {
            return res.status(404).json({ error: 'El estudiante no está inscrito en esta clase' });
        }

        // Dar de baja al estudiante
        await db.collection('classes').updateOne(
            { _id },
            {
                $pull: { students: studentObjectId },
                $set: { updatedAt: new Date() }
            }
        );

        // Also remove the student from future scheduled instances of this class
        try {
            const now = new Date();
            await db.collection('classInstances').updateMany(
                { classId: _id, dateTime: { $gte: now }, status: 'scheduled' },
                { $pull: { students: studentObjectId }, $set: { updatedAt: new Date() } }
            );
        } catch (e) {
            console.warn('Warning: failed to remove student from classInstances', e);
        }

        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al dar de baja estudiante' });
    }
});

// Cancelar clase para un alumno (genera un ticket de crédito) - puede hacerlo el propio alumno o admin/superusuario
app.post('/api/students/:id/cancel/:classId', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }

    const { id, classId } = req.params;
    // Permitir si es admin/superusuario o es el propio alumno
    if (!['administrador', 'superusuario'].includes(payload.role) && payload.id !== id) {
        return res.status(403).json({ error: 'No tienes permisos para cancelar esta clase' });
    }

    try {
        const studentObjectId = new ObjectId(id);
        const classObjectId = new ObjectId(classId);

        const classDoc = await db.collection('classes').findOne({ _id: classObjectId });
        if (!classDoc) return res.status(404).json({ error: 'Clase no encontrada' });

        // Ensure the class belongs to the same gym as the requester (unless superusuario)
        if (payload.role !== 'superusuario' && classDoc.gymId && classDoc.gymId !== payload.gymId) {
            return res.status(403).json({ error: 'No tenés permisos para cancelar esta clase' });
        }

        // Verificar que el alumno esté inscrito
        if (!classDoc.students || !classDoc.students.some(sid => sid.toString() === id)) {
            return res.status(404).json({ error: 'El estudiante no está inscrito en esta clase' });
        }

        // Remover al estudiante de la clase
        await db.collection('classes').updateOne(
            { _id: classObjectId },
            { $pull: { students: studentObjectId }, $set: { updatedAt: new Date() } }
        );

        // Obtener configuración del gimnasio para duración de crédito
        const gym = await db.collection('gyms').findOne({}) || DEFAULT_GYM_CONFIG;
        const creditDays = gym.creditExpirationDays || DEFAULT_GYM_CONFIG.creditExpirationDays;

        // Crear ticket de crédito y persistir en el documento del alumno
        const ticket = {
            id: new ObjectId().toString(),
            classId: classId,
            classSnapshot: {
                days: classDoc.days,
                start: classDoc.start,
                duration: classDoc.duration,
                roomId: classDoc.roomId,
                professorId: classDoc.professorId
            },
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + creditDays * 24 * 60 * 60 * 1000),
            status: 'active'
        };

        await db.collection('users').updateOne(
            { _id: studentObjectId },
            { $push: { tickets: ticket }, $set: { updatedAt: new Date() } }
        );

        res.json({ ticket });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al cancelar clase y crear ticket' });
    }
});

// Recuperar una clase usando un ticket (el alumno o admin pueden ejecutar)
app.post('/api/students/:id/recover/:classId', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }

    const { id, classId } = req.params;
    const { ticketId } = req.body;
    if (!ticketId) return res.status(400).json({ error: 'ticketId es requerido' });

    // Permitir si es admin/superusuario o es el propio alumno
    if (!['administrador', 'superusuario'].includes(payload.role) && payload.id !== id) {
        return res.status(403).json({ error: 'No tienes permisos para recuperar esta clase' });
    }

    try {
        const studentObjectId = new ObjectId(id);
        const classObjectId = new ObjectId(classId);

        const user = await db.collection('users').findOne({ _id: studentObjectId });
        if (!user) return res.status(404).json({ error: 'Alumno no encontrado' });

        const ticket = (user.tickets || []).find(t => t.id === ticketId);
        if (!ticket) return res.status(404).json({ error: 'Ticket no encontrado' });
        if (ticket.status !== 'active') return res.status(400).json({ error: 'Ticket ya fue usado o no está activo' });
        if (new Date(ticket.expiresAt) < new Date()) return res.status(400).json({ error: 'Ticket expirado' });
        if (ticket.classId !== classId) return res.status(400).json({ error: 'El ticket no corresponde a esta clase' });

        const classDoc = await db.collection('classes').findOne({ _id: classObjectId });
        if (!classDoc) return res.status(404).json({ error: 'Clase no encontrada' });

        // Ensure the class belongs to the same gym as the requester (unless superusuario)
        if (payload.role !== 'superusuario' && classDoc.gymId && classDoc.gymId !== payload.gymId) {
            return res.status(403).json({ error: 'No tenés permisos para recuperar esta clase' });
        }

        // Verificar capacidad
        const room = classDoc.roomId ? await db.collection('rooms').findOne({ _id: new ObjectId(classDoc.roomId) }) : null;
        const studentsCount = Array.isArray(classDoc.students) ? classDoc.students.length : 0;
        const capacity = room ? room.capacity : 0;
        if (studentsCount >= capacity) {
            return res.status(400).json({ error: 'La clase está llena' });
        }

        // Inscribir nuevamente al alumno
        await db.collection('classes').updateOne(
            { _id: classObjectId },
            { $push: { students: studentObjectId }, $set: { updatedAt: new Date() } }
        );

        // Marcar ticket como usado
        await db.collection('users').updateOne(
            { _id: studentObjectId, 'tickets.id': ticketId },
            { $set: { 'tickets.$.status': 'used', 'tickets.$.usedAt': new Date(), updatedAt: new Date() } }
        );

        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al recuperar clase con ticket' });
    }
});

// Listar estudiantes de una clase
app.get('/api/classes/:id/students', authMiddleware, async (req, res) => {
    const { id } = req.params;

    try {
        const _id = new ObjectId(id);

        // Obtener la clase
        const classDoc = await db.collection('classes').findOne({ _id });
        if (!classDoc)
            return res.status(404).json({ error: 'Clase no encontrada' });

        // Ensure the requester can access this class (same gym or superusuario)
        if (req.user.role !== 'superusuario' && classDoc.gymId && classDoc.gymId !== req.user.gymId) {
            return res.status(403).json({ error: 'No tenés permisos para ver los estudiantes de esta clase' });
        }

        // Si no hay estudiantes, devolver array vacío
        if (!classDoc.students || classDoc.students.length === 0) {
            return res.json([]);
        }

        // Obtener detalles de los estudiantes
        const students = await db.collection('users')
            .find({
                _id: { $in: classDoc.students },
                role: 'alumno'
            })
            .project({ password: 0 }) // Excluir contraseña
            .toArray();

        res.json(students);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al listar estudiantes' });
    }
});

// Superusuario: crear administrador + gym
app.post('/api/superusuario/admins', authMiddleware, async (req, res) => {
    // Only superusuario may call
    if (!req.user || req.user.role !== 'superusuario') return res.status(403).json({ error: 'No tenés permisos' });
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email y password son requeridos' });
    try {
        // verificar email unico
        const exists = await db.collection('users').findOne({ email });
        if (exists) return res.status(409).json({ error: 'Ya existe un usuario con ese email' });

        // crear gym
        const newGymId = new ObjectId().toString();
        await db.collection('gyms').insertOne({ gymId: newGymId, ...DEFAULT_GYM_CONFIG, createdAt: new Date() });

        // crear administrador
        const hashed = await bcrypt.hash(password, 10);
        const admin = {
            email,
            password: hashed,
            role: 'administrador',
            gymId: newGymId,
            createdAt: new Date()
        };
        const result = await db.collection('users').insertOne(admin);
        res.json({ id: result.insertedId, gymId: newGymId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error creando administrador' });
    }
});

// Serve static files in workspace root
app.use(express.static(path.join(__dirname)));

// Handle JSON parse errors from body-parser and return JSON instead of HTML
// This prevents the client from receiving an HTML error page when it sent
// malformed JSON (which previously caused the client to try parsing '<!DOCTYPE' as JSON).
app.use((err, req, res, next) => {
    if (err && err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        console.error('Invalid JSON payload:', err && err.message ? err.message : err);
        return res.status(400).json({ error: 'Invalid JSON payload' });
    }
    next(err);
});

const PORT = process.env.PORT || 3000;

connectDB().then(async () => {
    // Generar instancias al iniciar el servidor
    await generateClassInstances(30);

    // Regenerar instancias cada 24 horas
    setInterval(() => generateClassInstances(30), 24 * 60 * 60 * 1000);

    app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
}).catch(err => {
    console.error('Failed to connect to DB', err);
    process.exit(1);
});
