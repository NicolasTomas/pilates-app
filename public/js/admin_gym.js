// admin_gym.js - gestión de la configuración del gimnasio
(function () {
    const API = '';
    function headers() {
        const t = localStorage.getItem('token');
        return { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' };
    }

    async function getConfig() {
        const res = await fetch(`${API}/api/gym/config`, { headers: headers() });
        if (!res.ok) throw new Error('Error obteniendo configuración');
        return res.json();
    }

    async function updateConfig(config) {
        const res = await fetch(`${API}/api/gym/config`, {
            method: 'PUT',
            headers: headers(),
            body: JSON.stringify(config)
        });
        if (!res.ok) throw new Error((await res.json()).error || 'Error actualizando configuración');
        return res.json();
    }

    window.adminGym = {
        getConfig,
        updateConfig
    };
})();