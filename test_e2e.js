const fetch = global.fetch || require('node-fetch');
const base = 'http://localhost:3001';

async function req(path, opts = {}) {
  const res = await fetch(base + path, opts);
  const text = await res.text();
  let body = text;
  try { body = JSON.parse(text); } catch (e) { }
  return { status: res.status, body };
}

(async () => {
  try {
    console.log('Logging superusuario...');
    let r = await req('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ dni: '40000004' }) });
    console.log('super login status', r.status, r.body);
    if (r.status !== 200) return;
    const superToken = r.body.token;

    const headersSuper = { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + superToken };

    console.log('\nCreating admin1...');
    r = await req('/api/superusuario/admins', { method: 'POST', headers: headersSuper, body: JSON.stringify({ email: 'admin1@example.com', password: 'P@ssw0rd1' }) });
    console.log('create admin1', r.status, r.body);

    console.log('\nCreating admin2...');
    r = await req('/api/superusuario/admins', { method: 'POST', headers: headersSuper, body: JSON.stringify({ email: 'admin2@example.com', password: 'P@ssw0rd2' }) });
    console.log('create admin2', r.status, r.body);

    console.log('\nLogin admin1...');
    r = await req('/api/admin/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'admin1@example.com', password: 'P@ssw0rd1' }) });
    console.log('login1', r.status, r.body);
    if (r.status !== 200) return;
    const token1 = r.body.token;

    console.log('\nLogin admin2...');
    r = await req('/api/admin/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'admin2@example.com', password: 'P@ssw0rd2' }) });
    console.log('login2', r.status, r.body);
    if (r.status !== 200) return;
    const token2 = r.body.token;

    const headers1 = { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token1 };
    const headers2 = { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token2 };

    console.log('\nCreate professor with admin1...');
    r = await req('/api/professors', { method: 'POST', headers: headers1, body: JSON.stringify({ dni: '30000003', name: 'Prof Uno', lastName: 'A', phone: '123' }) });
    console.log('prof create', r.status, r.body);
    const profId = r.body && r.body.id;

    console.log('\nCreate room with admin1...');
    r = await req('/api/rooms', { method: 'POST', headers: headers1, body: JSON.stringify({ name: 'Sala A', capacity: 5 }) });
    console.log('room create', r.status, r.body);
    const roomId = r.body && r.body.id;

    console.log('\nCreate class with admin1...');
    r = await req('/api/classes', { method: 'POST', headers: headers1, body: JSON.stringify({ days: ['lunes'], start: '10:00', duration: 60, roomId: roomId, professorId: profId }) });
    console.log('class create', r.status, r.body);
    const classId = r.body && r.body.id;

    console.log('\nAdmin2 attempts to delete class created by admin1...');
    r = await req('/api/classes/' + classId, { method: 'DELETE', headers: headers2 });
    console.log('admin2 delete class', r.status, r.body);

    console.log('\nList rooms as admin2...');
    r = await req('/api/rooms', { method: 'GET', headers: headers2 });
    console.log('admin2 rooms', r.status, r.body);

    console.log('\nE2E test finished');
  } catch (e) {
    console.error('Test error', e);
  }
})();