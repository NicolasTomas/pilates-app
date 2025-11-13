// scripts/apply_new_gymid.js
// Creates a new gymId and assigns it to users/rooms/classes missing gymId
// Usage: node scripts/apply_new_gymid.js

const { MongoClient, ObjectId } = require('mongodb');
require('dotenv').config();

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017';
const DB_NAME = process.env.DB_NAME || 'pilatesdb';

(async function main(){
  const client = new MongoClient(MONGO_URI, { useUnifiedTopology: true });
  try{
    await client.connect();
    const db = client.db(DB_NAME);

    const newGymId = new ObjectId();
    console.log('Generated new gymId:', newGymId.toString());

    // Optionally insert into gyms collection if it exists; if not, create it
    try{
      const gymsColl = db.collection('gyms');
      const insertResult = await gymsColl.insertOne({ _id: newGymId, name: 'Auto gym ' + (new Date()).toISOString(), createdAt: new Date() });
      console.log('Inserted new gym document:', insertResult.insertedId);
    }catch(e){
      console.warn('Failed to insert into gyms collection (it may not exist). Continuing to assign gymId to documents. Error:', e && e.message ? e.message : e);
    }

    // Update users missing gymId
    const usersRes = await db.collection('users').updateMany({ $or: [ { gymId: { $exists: false } }, { gymId: null } ] }, { $set: { gymId: newGymId, updatedAt: new Date() } });
    console.log('Users modifiedCount:', usersRes.modifiedCount != null ? usersRes.modifiedCount : (usersRes.result && usersRes.result.nModified));

    // Update rooms missing gymId
    const roomsRes = await db.collection('rooms').updateMany({ $or: [ { gymId: { $exists: false } }, { gymId: null } ] }, { $set: { gymId: newGymId, updatedAt: new Date() } });
    console.log('Rooms modifiedCount:', roomsRes.modifiedCount != null ? roomsRes.modifiedCount : (roomsRes.result && roomsRes.result.nModified));

    // Update classes missing gymId
    const classesRes = await db.collection('classes').updateMany({ $or: [ { gymId: { $exists: false } }, { gymId: null } ] }, { $set: { gymId: newGymId, updatedAt: new Date() } });
    console.log('Classes modifiedCount:', classesRes.modifiedCount != null ? classesRes.modifiedCount : (classesRes.result && classesRes.result.nModified));

    console.log('\nAssignment complete. Please restart server and verify the UI.');
    process.exit(0);
  }catch(err){
    console.error('Error:', err && err.message ? err.message : err);
    process.exit(2);
  }finally{
    try{ await client.close(); }catch(e){}
  }
})();
