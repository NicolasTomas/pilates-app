// scripts/list_gymids.js
// Prints distinct gymId values found in classes, rooms and users
const { MongoClient, ObjectId } = require('mongodb');
require('dotenv').config();

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017';
const DB_NAME = process.env.DB_NAME || 'pilatesdb';

(async function(){
  const client = new MongoClient(MONGO_URI, { useUnifiedTopology: true });
  try{
    await client.connect();
    const db = client.db(DB_NAME);
    const classes = await db.collection('classes').aggregate([
      { $match: { } },
      { $group: { _id: { $ifNull: ["$gymId", null] }, count: { $sum: 1 } } }
    ]).toArray();
    const rooms = await db.collection('rooms').aggregate([
      { $match: { } },
      { $group: { _id: { $ifNull: ["$gymId", null] }, count: { $sum: 1 } } }
    ]).toArray();
    const users = await db.collection('users').aggregate([
      { $match: { } },
      { $group: { _id: { $ifNull: ["$gymId", null] }, count: { $sum: 1 } } }
    ]).toArray();

    console.log('Classes gymId counts:');
    console.log(classes);
    console.log('\nRooms gymId counts:');
    console.log(rooms);
    console.log('\nUsers gymId counts:');
    console.log(users);

    // list distinct non-null gymIds
    const distinct = await db.collection('classes').distinct('gymId');
    console.log('\nDistinct gymIds in classes (sample):', distinct.filter(Boolean));

    process.exit(0);
  }catch(err){
    console.error('Error:', err && err.message ? err.message : err);
    process.exit(2);
  }finally{
    try{ await client.close(); }catch(e){}
  }
})();
