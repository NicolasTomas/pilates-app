// scripts/inspect_fix_gymid.js
// Usage:
//  node scripts/inspect_fix_gymid.js --userId=<id> --classId=<id> --roomId=<id> [--apply=user|room|both]
//  node scripts/inspect_fix_gymid.js --scan [--apply=rooms]
//  If --apply is provided for specific ids, the script will perform the update(s).
//  In --scan mode the script runs read-only unless --apply=rooms is provided, which will
//  attempt a conservative automatic assignment of gymId to rooms when safe.

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
    const { userId, classId, roomId, apply, scan } = args;

    if (!scan && !userId && !classId && !roomId) {
        console.error('Please provide at least one of --userId, --classId or --roomId, or use --scan');
        process.exit(1);
    }

    let client = new MongoClient(MONGO_URI, { useUnifiedTopology: true });
    try {
        try {
            await client.connect();
        } catch (connectErr) {
            console.warn('Initial MongoDB connection failed:', connectErr && connectErr.message ? connectErr.message : connectErr);
            console.warn('Retrying with tlsAllowInvalidCertificates=true (unsafe).');
            client = new MongoClient(MONGO_URI, { useUnifiedTopology: true, tlsAllowInvalidCertificates: true });
            await client.connect();
        }
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

        // If scan mode, perform broader checks
        if (scan) {
            console.log('\n=== SCAN MODE ===');
            // users without gymId
            const usersNoGym = await db.collection('users').find({ $or: [{ gymId: { $exists: false } }, { gymId: null }] }).project({ _id: 1, role: 1, email: 1 }).toArray();
            console.log('Users without gymId:', usersNoGym.length);
            if (usersNoGym.length) console.log(usersNoGym.map(u => ({ _id: u._id, role: u.role, email: u.email })));

            // rooms without gymId
            const roomsNoGym = await db.collection('rooms').find({ $or: [{ gymId: { $exists: false } }, { gymId: null }] }).project({ _id: 1, name: 1 }).toArray();
            console.log('Rooms without gymId:', roomsNoGym.length);
            if (roomsNoGym.length) console.log(roomsNoGym.map(r => ({ _id: r._id, name: r.name })));

            // classes whose roomId doesn't exist in rooms
            const classes = await db.collection('classes').find({}).project({ _id: 1, roomId: 1, gymId: 1 }).toArray();
            const roomIds = (await db.collection('rooms').find({}).project({ _id: 1 }).toArray()).map(r => String(r._id));
            const classesOrphan = classes.filter(c => c.roomId && !roomIds.includes(String(c.roomId)));
            console.log('Classes with missing room (orphan roomId):', classesOrphan.length);
            if (classesOrphan.length) console.log(classesOrphan.map(c => ({ _id: c._id, roomId: c.roomId, gymId: c.gymId })));

            // rooms that are missing gymId but are referenced by classes with a unique gymId -> safe to assign
            const roomsToConsider = roomsNoGym.map(r => String(r._id));
            const safeAssigns = [];
            if (roomsToConsider.length) {
                for (const rid of roomsToConsider) {
                    const refClasses = classes.filter(c => c.roomId && String(c.roomId) === rid && c.gymId);
                    const uniqueGyms = [...new Set(refClasses.map(c => String(c.gymId)))];
                    if (uniqueGyms.length === 1) {
                        safeAssigns.push({ roomId: rid, suggestedGymId: uniqueGyms[0], sampleClassCount: refClasses.length });
                    }
                }
            }
            console.log('Conservative safe room->gymId assignments found:', safeAssigns.length);
            if (safeAssigns.length) console.log(safeAssigns);

            // users that are missing gymId but referenced by classes (as professor or student) with a unique gymId -> safe to assign
            const userSafeAssigns = [];
            if (usersNoGym.length) {
                const usersIds = usersNoGym.map(u => String(u._id));
                for (const uid of usersIds) {
                    const refClasses = classes.filter(c => (c.professorId && String(c.professorId) === uid) || (Array.isArray(c.students) && c.students.map(s => String(s)).includes(uid)));
                    const uniqueGyms = [...new Set(refClasses.filter(c => c.gymId).map(c => String(c.gymId)))];
                    if (uniqueGyms.length === 1) {
                        userSafeAssigns.push({ userId: uid, suggestedGymId: uniqueGyms[0], sampleClassCount: refClasses.length });
                    }
                }
            }
            console.log('Conservative safe user->gymId assignments found:', userSafeAssigns.length);
            if (userSafeAssigns.length) console.log(userSafeAssigns);

            // If --apply includes rooms or users, perform the safe assignments
            const doRooms = apply === 'rooms' || apply === 'both';
            const doUsers = apply === 'users' || apply === 'both';

            if ((doRooms && safeAssigns.length) || (doUsers && userSafeAssigns.length)) {
                console.log('--apply detected — will perform conservative assignments');
            }

            if (doRooms && safeAssigns.length) {
                console.log('--apply=rooms detected — applying safe room gymId assignments');
                for (const s of safeAssigns) {
                    try {
                        const r = await db.collection('rooms').updateOne({ _id: new ObjectId(s.roomId) }, { $set: { gymId: new ObjectId(s.suggestedGymId), updatedAt: new Date() } });
                        console.log('Updated room', s.roomId, 'modifiedCount:', r.modifiedCount != null ? r.modifiedCount : (r.result && r.result.nModified));
                    } catch (e) {
                        console.error('Failed to update room', s.roomId, e && e.message ? e.message : e);
                    }
                }
            }

            if (doUsers && userSafeAssigns.length) {
                console.log('--apply=users detected — applying safe user gymId assignments');
                for (const s of userSafeAssigns) {
                    try {
                        const r = await db.collection('users').updateOne({ _id: new ObjectId(s.userId) }, { $set: { gymId: new ObjectId(s.suggestedGymId), updatedAt: new Date() } });
                        console.log('Updated user', s.userId, 'modifiedCount:', r.modifiedCount != null ? r.modifiedCount : (r.result && r.result.nModified));
                    } catch (e) {
                        console.error('Failed to update user', s.userId, e && e.message ? e.message : e);
                    }
                }
            }

            if (!doRooms && !doUsers) {
                console.log('No --apply provided — scan ran read-only. To apply safe fixes, re-run with --apply=rooms, --apply=users or --apply=both');
            }

            process.exit(0);
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
