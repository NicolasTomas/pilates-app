// generate_instances.js
// Generates classInstances for all classes for the next N days.
const { MongoClient } = require('mongodb');
require('dotenv').config();

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017';
const DB_NAME = process.env.DB_NAME || 'pilatesdb';
const DAYS_AHEAD = process.env.DAYS_AHEAD ? Number(process.env.DAYS_AHEAD) : 30;

(async function main() {
    const client = new MongoClient(MONGO_URI);
    try {
        await client.connect();
        const db = client.db(DB_NAME);
        console.log('Connected to', MONGO_URI, DB_NAME);

        const classes = await db.collection('classes').find({}).toArray();
        console.log('Found', classes.length, 'classes');

        const daysNames = ['domingo', 'lunes', 'martes', 'miercoles', 'jueves', 'viernes', 'sabado'];
        const strip = (s = '') => s.toString().normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();

        const today = new Date();
        today.setHours(0, 0, 0, 0);

        let created = 0;
        for (const clase of classes) {
            for (let dayOffset = 0; dayOffset < DAYS_AHEAD; dayOffset++) {
                const targetDate = new Date(today);
                targetDate.setDate(today.getDate() + dayOffset);
                const dayName = daysNames[targetDate.getDay()];
                const claseDaysNormalized = Array.isArray(clase.days) ? clase.days.map(d => strip(d)) : [];
                if (!claseDaysNormalized.includes(strip(dayName))) continue;

                const [hours, minutes] = (clase.start || '00:00').split(':').map(Number);
                const instanceDateTime = new Date(targetDate);
                instanceDateTime.setHours(hours, minutes, 0, 0);

                const exists = await db.collection('classInstances').findOne({ classId: clase._id, dateTime: instanceDateTime });
                if (!exists) {
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
                    created++;
                }
            }
        }

        console.log('Generation done. Instances created:', created);
        process.exit(0);
    } catch (err) {
        console.error('Error', err);
        process.exit(2);
    } finally {
        try { await client.close(); } catch (e) { }
    }
})();
