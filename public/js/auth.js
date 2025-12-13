// Funciones para login/logout y verificacion de token
const API_BASE = '';

async function loginDni(dni) {
    const res = await fetch(`${API_BASE}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dni })
    });
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || 'Login failed');
    }
    const data = await res.json();
    localStorage.setItem('token', data.token);
    localStorage.setItem('role', data.role);
    return data;
}

async function adminLogin(email, password) {
    const res = await fetch(`${API_BASE}/api/admin/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
    });
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || 'Mail o contraseña incorrectas');
    }
    const data = await res.json();
    localStorage.setItem('token', data.token);
    localStorage.setItem('role', data.role);
    return data;
}

function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('role');
    window.location.href = '/index.html';
}

async function getMe() {
    const token = localStorage.getItem('token');
    if (!token) throw new Error('No token');
    const res = await fetch(`${API_BASE}/api/me`, {
        headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) {
        throw new Error('Not authorized');
    }
    return res.json();
}

async function checkSessionAndRedirect(allowedRoles = null) {
    const token = localStorage.getItem('token');
    if (!token) {
        window.location.href = '/index.html';
        throw new Error('No token found');
    }
    try {
        const me = await getMe();
        if (allowedRoles && !allowedRoles.includes(me.role)) {
            alert('No tenés permiso para ver esta página');
            window.location.href = '/index.html';
            throw new Error('Unauthorized role');
        }
        return me;
    } catch (err) {
        localStorage.removeItem('token');
        localStorage.removeItem('role');
        window.location.href = '/index.html';
        throw err;
    }
}

function ensureRole(allowedRoles) {
    return async function () {
        try {
            const me = await getMe();
            if (!allowedRoles.includes(me.role)) {
                alert('No tenés permiso para ver esta página');
                window.location.href = '/index.html';
            }
            return me;
        } catch (err) {
            console.warn('Auth failed', err);
            window.location.href = '/index.html';
        }
    }
}

// Exports for browser
window.pilatesAuth = { loginDni, adminLogin, logout, getMe, ensureRole, checkSessionAndRedirect };
