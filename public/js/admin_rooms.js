// admin_rooms.js - gestión de salones (rooms)
(async function () {
    const API = '';
    function tokenHeader() {
        const t = localStorage.getItem('token');
        return { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' };
    }

    async function listRooms() {
        const res = await fetch(`${API}/api/rooms`, { headers: tokenHeader() });
        if (!res.ok) throw new Error('No autorizado');
        return res.json();
    }

    async function createRoom(name, capacity) {
        const res = await fetch(`${API}/api/rooms`, { method: 'POST', headers: tokenHeader(), body: JSON.stringify({ name, capacity }) });
        return res.json();
    }

    async function updateRoom(id, name, capacity) {
        const res = await fetch(`${API}/api/rooms/${id}`, { method: 'PUT', headers: tokenHeader(), body: JSON.stringify({ name, capacity }) });
        return res.json();
    }

    async function deleteRoom(id) {
        const res = await fetch(`${API}/api/rooms/${id}`, { method: 'DELETE', headers: tokenHeader() });
        return res.json();
    }

    // UI bindings
    window.adminRooms = {
        listRooms, createRoom, updateRoom, deleteRoom
    };
})();
