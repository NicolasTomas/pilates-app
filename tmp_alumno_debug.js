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
        console.log('=== DIAGNÓSTICO PANEL ALUMNO ===\n');

        // 1) Login
        console.log('1) Login alumno DNI 10000001...');
        const login = await request({ path: '/api/login', method: 'POST', body: { dni: '10000001' } });
        console.log('   Status:', login.status);
        if (login.status !== 200) throw new Error('Login falló: ' + JSON.stringify(login.body));
        const token = login.body.token;
        console.log('   ✓ Token obtenido\n');

        // 2) /api/me
        console.log('2) GET /api/me...');
        const me = await request({ path: '/api/me', token });
        console.log('   Status:', me.status);
        console.log('   Body:', me.body);
        if (me.status !== 200) throw new Error('/api/me falló');
        const studentId = me.body.id;
        console.log('   ✓ ID:', studentId, '\n');

        // 3) Config pública
        console.log('3) GET /api/gym/config/public...');
        const config = await request({ path: '/api/gym/config/public' });
        console.log('   Status:', config.status);
        console.log('   Body:', config.body);
        if (config.status !== 200) console.warn('   ⚠ Config pública no disponible');
        else console.log('   ✓ Config obtenida\n');

        // 4) Datos del alumno
        console.log('4) GET /api/students/' + studentId + '...');
        const student = await request({ path: `/api/students/${studentId}`, token });
        console.log('   Status:', student.status);
        console.log('   Body:', JSON.stringify(student.body, null, 2));
        if (student.status !== 200) throw new Error('GET student falló: ' + JSON.stringify(student.body));
        console.log('   ✓ Alumno obtenido\n');

        // 5) Clases del alumno
        console.log('5) GET /api/students/' + studentId + '/classes...');
        const classes = await request({ path: `/api/students/${studentId}/classes`, token });
        console.log('   Status:', classes.status);
        console.log('   Body:', JSON.stringify(classes.body, null, 2));
        if (classes.status !== 200) console.warn('   ⚠ Classes falló');
        else console.log('   ✓ Clases obtenidas:', Array.isArray(classes.body) ? classes.body.length : 'N/A', '\n');

        console.log('=== TODO OK - PANEL DEBE CARGAR ===');
        process.exit(0);
    } catch (err) {
        console.error('❌ ERROR:', err.message);
        process.exit(1);
    }
})();
