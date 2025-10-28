const http = require('http');

function request(options, body) {
    return new Promise((resolve, reject) => {
        const req = http.request(options, res => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try { resolve({ status: res.statusCode, body: JSON.parse(data || '{}') }); }
                catch (e) { resolve({ status: res.statusCode, body: data }); }
            });
        });
        req.on('error', reject);
        if (body) req.write(JSON.stringify(body));
        req.end();
    });
}

(async () => {
    try {
        const login = await request({ hostname: 'localhost', port: 3000, path: '/api/login', method: 'POST', headers: { 'Content-Type': 'application/json' } }, { dni: '10000001' });
        console.log('LOGIN', login.status, login.body);
        const token = login.body.token;

        const me = await request({ hostname: 'localhost', port: 3000, path: '/api/me', method: 'GET', headers: { Authorization: `Bearer ${token}` } });
        console.log('/api/me', me.status, me.body);

        const studentId = me.body.id;
        const classes = await request({ hostname: 'localhost', port: 3000, path: `/api/students/${studentId}/classes`, method: 'GET', headers: { Authorization: `Bearer ${token}` } });
        console.log('/api/students/:id/classes', classes.status, classes.body);
    } catch (e) { console.error(e); process.exit(1) }
})();