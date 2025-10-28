const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017';
const DB_NAME = process.env.DB_NAME || 'pilatesdb';

async function seed() {
    const client = new MongoClient(MONGO_URI);
    await client.connect();
    const db = client.db(DB_NAME);

    // Limpiar colecciones
    await db.collection('users').deleteMany({});
    await db.collection('rooms').deleteMany({});
    await db.collection('classes').deleteMany({});
    await db.collection('classInstances').deleteMany({});

    // Crear salón
    const room = {
        name: 'Sala Principal',
        capacity: 10
    };
    const roomResult = await db.collection('rooms').insertOne(room);
    const roomId = roomResult.insertedId;

    // Crear profesor
    const prof = {
        dni: '20000002',
        name: 'Juan',
        lastName: 'Profesor',
        role: 'profesor',
        createdAt: new Date()
    };
    const profResult = await db.collection('users').insertOne(prof);
    const profId = profResult.insertedId;

    // Crear clase y asignar profesor
    const clase = {
        days: ['lunes', 'miércoles', 'viernes'],
        start: '18:00',
        duration: 60,
        roomId: roomId,
        professorId: profId,
        students: [],
        createdAt: new Date()
    };
    const claseResult = await db.collection('classes').insertOne(clase);
    const claseId = claseResult.insertedId;

    // Crear alumno
    const alumna = {
        dni: '10000001',
        name: 'María',
        lastName: 'Alumna',
        role: 'alumno',
        phone: '555-0001',
        emergencyContact: 'Juan Alumno 555-0002',
        dueDate: new Date('2025-12-31'),
        membershipType: 'mensual',
        createdAt: new Date()
    };
    const alumnaResult = await db.collection('users').insertOne(alumna);
    const alumnaId = alumnaResult.insertedId;

    // Asignar alumno a la clase (patrón recurrente)
    await db.collection('classes').updateOne(
        { _id: claseId },
        { $push: { students: alumnaId } }
    );

    // Generar instancias de ejemplo (próximas 2 semanas)
    const daysMap = { 'lunes': 1, 'miércoles': 3, 'viernes': 5 };
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    for (let dayOffset = 0; dayOffset < 14; dayOffset++) {
        const targetDate = new Date(today);
        targetDate.setDate(today.getDate() + dayOffset);
        const dayOfWeek = targetDate.getDay();

        if (Object.values(daysMap).includes(dayOfWeek)) {
            const instanceDateTime = new Date(targetDate);
            instanceDateTime.setHours(18, 0, 0, 0);

            await db.collection('classInstances').insertOne({
                classId: claseId,
                dateTime: instanceDateTime,
                duration: 60,
                roomId: roomId,
                professorId: profId,
                students: [alumnaId],
                status: 'scheduled',
                createdAt: new Date()
            });
        }
    }

    // Crear superusuario
    const superusuario = {
        dni: '40000004',
        name: 'Súper',
        lastName: 'Usuario',
        role: 'superusuario',
        createdAt: new Date()
    };
    await db.collection('users').insertOne(superusuario);

    // crear administrador con email y password
    const adminPassword = 'AdminPass123!';
    const hashed = await bcrypt.hash(adminPassword, 10);
    const admin = { email: 'admin@pilates.local', name: 'Ana Administradora', role: 'administrador', password: hashed, createdAt: new Date() };
    await db.collection('users').insertOne(admin);

    console.log('Seed completed');
    console.log(`Admin credentials: email=${admin.email} password=${adminPassword}`);
    await client.close();
}

seed().catch(err => {
    console.error(err);
    process.exit(1);
});
