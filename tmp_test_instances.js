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
        console.log('=== TEST INSTANCIAS DE CLASES ===\n');

        // Login
        const login = await request({ path: '/api/login', method: 'POST', body: { dni: '10000001' } });
        const token = login.body.token;
        const me = await request({ path: '/api/me', token });
        const studentId = me.body.id;

        console.log('1) Obtener instancias del alumno...');
        const instances = await request({ path: `/api/students/${studentId}/class-instances`, token });
        console.log('   Status:', instances.status);
        console.log('   Instancias:', instances.body.length);
        if (instances.body.length > 0) {
            instances.body.slice(0, 3).forEach((inst, i) => {
                const dt = new Date(inst.dateTime);
                console.log(`   ${i + 1}. ${dt.toLocaleDateString('es-AR')} ${dt.toLocaleTimeString('es-AR', { hour: '2-digit', minute: '2-digit' })} - ${inst.roomName} - ${inst.camillasFree} libres`);
            });
        }

        console.log('\n2) Obtener instancias disponibles para recuperar...');
        const available = await request({ path: '/api/class-instances/available', token });
        console.log('   Status:', available.status);
        console.log('   Disponibles:', available.body.length);
        if (available.body.length > 0) {
            available.body.slice(0, 3).forEach((inst, i) => {
                const dt = new Date(inst.dateTime);
                console.log(`   ${i + 1}. ${dt.toLocaleDateString('es-AR')} ${dt.toLocaleTimeString('es-AR', { hour: '2-digit', minute: '2-digit' })} - ${inst.roomName} - ${inst.camillasFree} libres`);
            });
        }

        if (instances.body.length > 0) {
            console.log('\n3) Cancelar primera instancia...');
            const firstInstance = instances.body[0];
            const cancel = await request({
                path: `/api/students/${studentId}/cancel-instance/${firstInstance._id}`,
                method: 'POST',
                token
            });
            console.log('   Status:', cancel.status);
            console.log('   Ticket generado:', cancel.body.ticket ? 'Sí' : 'No');
            console.log('   Mensaje:', cancel.body.message || '');

            if (cancel.body.ticket) {
                console.log('\n4) Verificar instancias después de cancelar...');
                const afterCancel = await request({ path: `/api/students/${studentId}/class-instances`, token });
                console.log('   Instancias restantes:', afterCancel.body.length);

                console.log('\n5) Recuperar instancia cancelada...');
                const recover = await request({
                    path: `/api/students/${studentId}/recover-instance/${firstInstance._id}`,
                    method: 'POST',
                    token,
                    body: { ticketId: cancel.body.ticket.id }
                });
                console.log('   Status:', recover.status);
                console.log('   Recuperado:', recover.body.ok ? 'Sí' : 'No');

                console.log('\n6) Verificar instancias después de recuperar...');
                const afterRecover = await request({ path: `/api/students/${studentId}/class-instances`, token });
                console.log('   Instancias finales:', afterRecover.body.length);
            }
        }

        console.log('\n=== TEST COMPLETO ===');
        process.exit(0);
    } catch (err) {
        console.error('❌ ERROR:', err.message);
        process.exit(1);
    }
})();
