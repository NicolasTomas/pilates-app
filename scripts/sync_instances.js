// sync_instances.js
// Usage: set env MONGO_URI and DB_NAME, then: node scripts/sync_instances.js

const { MongoClient, ObjectId } = require('mongodb');
require('dotenv').config();

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017';
const DB_NAME = process.env.DB_NAME || 'pilatesdb';

(async function main() {
    const client = new MongoClient(MONGO_URI);
    try {
        await client.connect();
        console.log('Connected to', MONGO_URI, DB_NAME);
        const db = client.db(DB_NAME);

        const now = new Date();
        const classesCursor = db.collection('classes').find({ students: { $exists: true, $ne: [] } });
        let count = 0;
        while (await classesCursor.hasNext()) {
            const clase = await classesCursor.next();
            const students = Array.isArray(clase.students) ? clase.students : [];
            if (!students.length) continue;
            const res = await db.collection('classInstances').updateMany(
                { classId: clase._id, dateTime: { $gte: now }, status: 'scheduled' },
                { $addToSet: { students: { $each: students } }, $set: { updatedAt: new Date() } }
            );
            console.log(`Class ${clase._id.toString()}: matched ${res.matchedCount}, modified ${res.modifiedCount}`);
            count += res.modifiedCount || 0;
        }

        console.log('Sync completed, total modified instances:', count);
        process.exit(0);
    } catch (err) {
        console.error('Sync failed', err);
        process.exit(2);
    } finally {
        try { await client.close(); } catch (e) { }
    }
})();
