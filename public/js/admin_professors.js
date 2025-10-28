// admin_professors.js - gestión de profesores
(function () {
    const API = '';
    function headers() {
        const t = localStorage.getItem('token');
        return { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' };
    }

    async function listProfessors() {
        const res = await fetch(`${API}/api/users?role=profesor`, { headers: headers() });
        if (!res.ok) throw new Error('Error listando profesores');
        return res.json();
    }

    async function createProfessor(professor) {
        const res = await fetch(`${API}/api/professors`, {
            method: 'POST',
            headers: headers(),
            body: JSON.stringify(professor)
        });
        if (!res.ok) throw new Error((await res.json()).error || 'Error creando profesor');
        return res.json();
    }

    async function deleteProfessor(id) {
        const res = await fetch(`${API}/api/professors/${id}`, {
            method: 'DELETE',
            headers: headers()
        });
        if (!res.ok) throw new Error((await res.json()).error || 'Error eliminando profesor');
        return res.json();
    }

    window.adminProfessors = {
        listProfessors,
        createProfessor,
        deleteProfessor
    };
})();