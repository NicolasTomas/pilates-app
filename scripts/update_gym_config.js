(async () => {
    try {
        const API = 'http://localhost:3000';
        // Admin login
        const login = await fetch(`${API}/api/admin/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: 'admin@pilates.local', password: 'AdminPass123!' })
        });
        if (!login.ok) return console.error('Admin login failed', await login.text());
        const jl = await login.json();
        const token = jl.token;
        console.log('Got admin token');

        const payload = { minCancellationHours: 24, creditExpirationDays: 30, autoCancelDueOverdueDays: 14, maxCredits: 10 };
        const res = await fetch(`${API}/api/gym/config`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
            body: JSON.stringify(payload)
        });
        console.log('Update status', res.status);
        console.log('Body:', await res.text());

        const pub = await fetch(`${API}/api/gym/config/public`);
        console.log('Public config:', await pub.json());
    } catch (e) {
        console.error('Error', e);
    }
})();
