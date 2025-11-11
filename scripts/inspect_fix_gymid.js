// scripts/inspect_fix_gymid.js
// Usage:
//  node scripts/inspect_fix_gymid.js --userId=<id> --classId=<id> --roomId=<id> [--apply=user|room|both]
//  If --apply is provided, the script will perform the update(s). Without --apply it only prints diagnostics.

const { MongoClient, ObjectId } = require('mongodb');
require('dotenv').config();

const MONGO_URI = process.env.MONGO_URI || process.env.FALLBACK_MONGO_URI || 'mongodb://localhost:27017';
const DB_NAME = process.env.DB_NAME || 'pilatesdb';

function parseArgs() {
    const args = {};
    for (const a of process.argv.slice(2)) {
        if (a.startsWith('--')) {
            const [k, v] = a.substring(2).split('=');
            args[k] = v === undefined ? true : v;
        }
    }
    return args;
}

(async function main() {
    const args = parseArgs();
    const { userId, classId, roomId, apply } = args;

    if (!userId && !classId && !roomId) {
        console.error('Please provide at least one of --userId, --classId or --roomId');
        process.exit(1);
    }

    const client = new MongoClient(MONGO_URI, { useUnifiedTopology: true });
    try {
        await client.connect();
        const db = client.db(DB_NAME);

        const out = {};

        if (userId) {
            try {
                const u = await db.collection('users').findOne({ _id: new ObjectId(userId) });
                out.user = u || null;
                console.log('USER:', u ? JSON.stringify({ _id: u._id, role: u.role, gymId: u.gymId, email: u.email, dni: u.dni }, null, 2) : 'NOT FOUND');
            } catch (e) { console.error('Failed to load user:', e.message); }
        }

        if (classId) {
            try {
                const c = await db.collection('classes').findOne({ _id: new ObjectId(classId) });
                out.class = c || null;
                console.log('CLASS:', c ? JSON.stringify({ _id: c._id, roomId: c.roomId, gymId: c.gymId }, null, 2) : 'NOT FOUND');
            } catch (e) { console.error('Failed to load class:', e.message); }
        }

        if (roomId) {
            try {
                const r = await db.collection('rooms').findOne({ _id: new ObjectId(roomId) });
                out.room = r || null;
                console.log('ROOM:', r ? JSON.stringify({ _id: r._id, name: r.name, gymId: r.gymId }, null, 2) : 'NOT FOUND');
            } catch (e) { console.error('Failed to load room:', e.message); }
        }

        // If we have class but not roomId, try to load room from class
        if (!roomId && out.class && out.class.roomId) {
            try {
                const r2 = await db.collection('rooms').findOne({ _id: new ObjectId(out.class.roomId) });
                out.roomFromClass = r2 || null;
                console.log('ROOM from CLASS.roomId:', r2 ? JSON.stringify({ _id: r2._id, name: r2.name, gymId: r2.gymId }, null, 2) : 'NOT FOUND');
            } catch (e) { console.error('Failed to load room from class:', e.message); }
        }

        // Determine suggested fixes if any
        const suggestions = [];
        const targetGym = (out.class && out.class.gymId) || (out.room && out.room.gymId) || (out.roomFromClass && out.roomFromClass.gymId) || null;
        if (userId && out.user) {
            if (!out.user.gymId && targetGym) {
                suggestions.push({ type: 'assignUserGym', reason: 'user has no gymId but class/room has gymId', suggestedGymId: targetGym });
            } else if (out.user.gymId && targetGym && String(out.user.gymId) !== String(targetGym)) {
                suggestions.push({ type: 'mismatchUserGym', reason: 'user.gymId differs from class/room gymId', userGymId: out.user.gymId, targetGymId: targetGym });
            }
        }
        if ((out.room || out.roomFromClass) && targetGym) {
            const roomDoc = out.room || out.roomFromClass;
            if (roomDoc && !roomDoc.gymId && targetGym) {
                suggestions.push({ type: 'assignRoomGym', reason: 'room has no gymId but class has gymId', suggestedGymId: targetGym });
            }
        }

        if (suggestions.length === 0) {
            console.log('No automatic suggestions detected. Review the printed documents for inconsistencies.');
        } else {
            console.log('SUGGESTIONS:', JSON.stringify(suggestions, null, 2));

            if (apply) {
                console.log('--apply flag detected. Will perform changes:', apply);
                // apply can be 'user', 'room', or 'both'
                const doUser = apply === 'user' || apply === 'both';
                const doRoom = apply === 'room' || apply === 'both';

                if (doUser && userId && out.user) {
                    const newGym = targetGym;
                    if (!newGym) {
                        console.error('No target gymId found to assign to user. Aborting user change.');
                    } else {
                        const r = await db.collection('users').updateOne({ _id: new ObjectId(userId) }, { $set: { gymId: newGym, updatedAt: new Date() } });
                        console.log('Updated user gymId result:', r.result || r);
                    }
                }

                if (doRoom) {
                    const roomToUpdate = out.room ? out.room : out.roomFromClass;
                    if (!roomToUpdate) {
                        console.error('No room doc available to update. Aborting room change.');
                    } else {
                        const newGym = targetGym;
                        if (!newGym) {
                            console.error('No target gymId found to assign to room. Aborting room change.');
                        } else {
                            const r = await db.collection('rooms').updateOne({ _id: roomToUpdate._id }, { $set: { gymId: newGym, updatedAt: new Date() } });
                            console.log('Updated room gymId result:', r.result || r);
                        }
                    }
                }
            } else {
                console.log('Run again with --apply=user or --apply=room or --apply=both to perform the suggested change(s).');
            }
        }

        process.exit(0);
    } catch (err) {
        console.error('Error:', err && err.message ? err.message : err);
        process.exit(2);
    } finally {
        try { await client.close(); } catch (e) { }
    }
})();
