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

        const daysMap = {
            'domingo': 0, 'lunes': 1, 'martes': 2, 'miércoles': 3,
            'jueves': 4, 'viernes': 5, 'sábado': 6
        };

        const today = new Date();
        today.setHours(0, 0, 0, 0);

        let created = 0;
        for (const clase of classes) {
            for (let dayOffset = 0; dayOffset < DAYS_AHEAD; dayOffset++) {
                const targetDate = new Date(today);
                targetDate.setDate(today.getDate() + dayOffset);
                const dayName = Object.keys(daysMap).find(k => daysMap[k] === targetDate.getDay());
                if (!clase.days || !clase.days.includes(dayName)) continue;

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
