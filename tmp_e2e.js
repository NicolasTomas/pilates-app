const http = require('http');

function request({ path, method = 'GET', token, body }) {
    const options = {
        hostname: 'localhost',
        port: 3000,
        path,
        method,
        headers: { 'Content-Type': 'application/json' }
    };
    if (token) options.headers.Authorization = `Bearer ${token}`;

    return new Promise((resolve, reject) => {
        const req = http.request(options, res => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                let parsed = data;
                try { parsed = JSON.parse(data || '{}'); } catch { }
                resolve({ status: res.statusCode, body: parsed });
            });
        });
        req.on('error', reject);
        if (body) req.write(JSON.stringify(body));
        req.end();
    });
}

(async () => {
    try {
        // 1) Login alumno
        const login = await request({ path: '/api/login', method: 'POST', body: { dni: '10000001' } });
        console.log('LOGIN:', login.status);
        if (login.status !== 200) throw new Error('Login failed: ' + JSON.stringify(login.body));
        const token = login.body.token;

        // 2) /api/me
        const me = await request({ path: '/api/me', method: 'GET', token });
        console.log('/api/me:', me.status, me.body.role, me.body.id);
        const studentId = me.body.id;

        // 3) Obtener clases del alumno
        let classes = await request({ path: `/api/students/${studentId}/classes`, method: 'GET', token });
        console.log('Clases iniciales:', classes.status, Array.isArray(classes.body) ? classes.body.length : classes.body);
        if (!Array.isArray(classes.body) || classes.body.length === 0) throw new Error('No hay clases asignadas para el alumno.');
        const classId = classes.body[0]._id || classes.body[0].id || classes.body[0].classId;

        // 4) Cancelar clase → genera ticket
        const cancelRes = await request({ path: `/api/students/${studentId}/cancel/${classId}`, method: 'POST', token });
        console.log('Cancelar clase:', cancelRes.status, cancelRes.body && cancelRes.body.ticket ? 'ticket creado' : cancelRes.body);
        if (cancelRes.status !== 200 || !cancelRes.body.ticket) throw new Error('Cancelación no generó ticket');
        const ticketId = cancelRes.body.ticket.id;

        // 5) Verificar que ya no aparezca la clase
        classes = await request({ path: `/api/students/${studentId}/classes`, method: 'GET', token });
        console.log('Clases post-cancel:', classes.status, Array.isArray(classes.body) ? classes.body.length : classes.body);

        // 6) Recuperar usando ticket
        const recoverRes = await request({ path: `/api/students/${studentId}/recover/${classId}`, method: 'POST', token, body: { ticketId } });
        console.log('Recuperar clase:', recoverRes.status, recoverRes.body);
        if (recoverRes.status !== 200) throw new Error('Recuperación falló');

        // 7) Verificar que vuelve a aparecer la clase
        classes = await request({ path: `/api/students/${studentId}/classes`, method: 'GET', token });
        console.log('Clases post-recover:', classes.status, Array.isArray(classes.body) ? classes.body.length : classes.body);

        console.log('E2E OK');
        process.exit(0);
    } catch (err) {
        console.error('E2E ERROR:', err.message);
        process.exit(1);
    }
})();
