const http = require('http');

function request({ path, method = 'GET', token, body, query }) {
    const options = {
        hostname: 'localhost',
        port: 3000,
        path: query ? `${path}?${new URLSearchParams(query).toString()}` : path,
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
        // 1) Login admin
        const adminLogin = await request({ path: '/api/admin/login', method: 'POST', body: { email: 'admin@pilates.local', password: 'AdminPass123!' } });
        console.log('ADMIN LOGIN:', adminLogin.status);
        if (adminLogin.status !== 200) throw new Error('Admin login failed: ' + JSON.stringify(adminLogin.body));
        const token = adminLogin.body.token;

        // 2) Crear alumno nuevo
        const dni = String(Math.floor(Math.random() * 90000000) + 10000000);
        const payload = {
            dni,
            name: 'Alumno',
            lastName: 'CreadoAdmin',
            phone: '555-0101',
            membershipType: 'mensual',
            emergencyContact: 'Contacto 555-0102',
            dueDate: '2025-12-31',
            classIds: []
        };
        const createRes = await request({ path: '/api/students', method: 'POST', token, body: payload });
        console.log('CREATE STUDENT:', createRes.status, createRes.body);
        if (createRes.status !== 200 || !createRes.body.id) throw new Error('Create student failed');

        // 3) Buscar por DNI para confirmar
        const listRes = await request({ path: '/api/users', method: 'GET', token, query: { role: 'alumno', search: dni } });
        console.log('LIST STUDENTS:', listRes.status, listRes.body);
        if (listRes.status === 200 && Array.isArray(listRes.body)) {
            const found = listRes.body.find(u => u.dni === dni);
            if (!found) throw new Error('Alumno no encontrado tras crear');
            console.log('Alumno creado OK en Atlas:', { id: found._id, dni: found.dni, name: found.name, lastName: found.lastName });
        } else {
            throw new Error('Listado no retornó array');
        }

        console.log('ADMIN CREATE CHECK OK');
        process.exit(0);
    } catch (err) {
        console.error('ADMIN CREATE CHECK ERROR:', err.message);
        process.exit(1);
    }
})();
