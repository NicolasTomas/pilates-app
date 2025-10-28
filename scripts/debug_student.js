const { MongoClient, ObjectId } = require('mongodb');
require('dotenv').config();

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017';
const DB_NAME = process.env.DB_NAME || 'pilatesdb';

(async function () {
    const client = new MongoClient(MONGO_URI);
    try {
        await client.connect();
        const db = client.db(DB_NAME);
        console.log('Connected to', MONGO_URI, DB_NAME);

        const student = await db.collection('users').findOne({ role: 'alumno' }, { sort: { createdAt: -1 } });
        if (!student) {
            console.log('No alumnos found');
            process.exit(0);
        }
        console.log('\n--- Student ---');
        console.log('id:', student._id.toString());
        console.log('name:', student.name, student.lastName);
        console.log('dni:', student.dni);
        console.log('gymId:', student.gymId);
        console.log('createdAt:', student.createdAt);
        console.log('tickets:', (student.tickets || []).length);

        // Classes containing student
        const classes = await db.collection('classes').find({ students: student._id }).toArray();
        console.log('\n--- Classes (classes.students includes student) ---');
        if (classes.length === 0) console.log('None');
        for (const c of classes) {
            console.log('class id:', c._id.toString(), 'days:', c.days, 'start:', c.start, 'gymId:', c.gymId, 'studentsCount:', (c.students || []).length);
        }

        // Instances containing student
        const now = new Date();
        const instances = await db.collection('classInstances').find({ students: student._id, dateTime: { $gte: now } }).sort({ dateTime: 1 }).toArray();
        console.log('\n--- Future classInstances where student is enrolled ---');
        if (instances.length === 0) console.log('None');
        for (const inst of instances) {
            console.log('instance id:', inst._id.toString(), 'classId:', inst.classId ? inst.classId.toString() : null, 'dateTime:', inst.dateTime, 'status:', inst.status, 'studentsCount:', (inst.students || []).length);
        }

        // Instances for classes the student is enrolled in (regardless of enrollment in instance)
        const classIds = classes.map(c => c._id);
        if (classIds.length > 0) {
            const insts = await db.collection('classInstances').find({ classId: { $in: classIds }, dateTime: { $gte: now } }).sort({ dateTime: 1 }).toArray();
            console.log('\n--- Future instances for those classes (regardless student membership) ---');
            for (const inst of insts) {
                const includes = Array.isArray(inst.students) && inst.students.some(s => s.toString() === student._id.toString());
                console.log('instance id:', inst._id.toString(), 'classId:', inst.classId ? inst.classId.toString() : null, 'dateTime:', inst.dateTime, 'status:', inst.status, 'studentsCount:', (inst.students || []).length, 'includesStudent:', includes);
            }
        }

    } catch (err) {
        console.error('Error', err);
        process.exit(2);
    } finally {
        try { await client.close(); } catch (e) { }
    }
})();
