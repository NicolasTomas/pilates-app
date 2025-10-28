require('dotenv').config();
const { MongoClient } = require('mongodb');
const uri = process.env.MONGO_URI || 'mongodb://localhost:27017';
const dbName = process.env.DB_NAME || 'pilatesdb';

(async () => {
    console.log('Trying to connect to MongoDB with URI:', uri);
    const client = new MongoClient(uri, { serverSelectionTimeoutMS: 5000 });
    try {
        await client.connect();
        const db = client.db(dbName);
        const admin = db.admin ? db.admin() : null;
        console.log('Connected OK to', uri, 'database:', dbName);
        const colls = await db.listCollections().toArray();
        console.log('Collections sample:', colls.map(c => c.name).slice(0, 10));
        await client.close();
        process.exit(0);
    } catch (err) {
        console.error('Connection error:');
        console.error(err && err.stack ? err.stack : err);
        process.exit(1);
    }
})();