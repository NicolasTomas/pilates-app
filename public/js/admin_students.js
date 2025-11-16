// admin_students.js - gestión de alumnos
(function () {
    const API = '';
    function headers() {
        const t = localStorage.getItem('token');
        return { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' };
    }

    async function listStudents(search = '') {
        // If role says 'profesor', call the professor-specific endpoint directly
        const role = localStorage.getItem('role');
        if (role === 'profesor') {
            try {
                if (!window.pilatesAuth || !window.pilatesAuth.getMe) throw new Error('No auth helper');
                const me = await window.pilatesAuth.getMe();
                const token = localStorage.getItem('token');
                const q = search ? `?search=${encodeURIComponent(search)}` : '';
                const profRes = await fetch(`${API}/api/professors/${me.id}/students${q}`, { headers: { Authorization: `Bearer ${token}` } });
                if (!profRes.ok) throw new Error('Error listando alumnos');
                return profRes.json();
            } catch (err) {
                throw new Error('Error listando alumnos');
            }
        }

        // Otherwise try admin users endpoint and fall back to professor endpoint on 403
        const res = await fetch(`${API}/api/users?role=alumno${search ? `&search=${search}` : ''}`, {
            headers: headers()
        });
        if (res.ok) return res.json();
        if (res.status === 401 || res.status === 403) {
            // fallback to professor endpoint if possible
            try {
                if (!window.pilatesAuth || !window.pilatesAuth.getMe) throw new Error('No auth helper');
                const me = await window.pilatesAuth.getMe();
                const profRes = await fetch(`${API}/api/professors/${me.id}/students${search ? `?search=${encodeURIComponent(search)}` : ''}`, { headers: headers() });
                if (!profRes.ok) throw new Error('Error listando alumnos');
                return profRes.json();
            } catch (err) {
                throw new Error('Error listando alumnos');
            }
        }

        throw new Error('Error listando alumnos');
    }

    async function createStudent(student) {
        const res = await fetch(`${API}/api/students`, {
            method: 'POST',
            headers: headers(),
            body: JSON.stringify(student)
        });
        if (!res.ok) throw new Error((await res.json()).error || 'Error creando alumno');
        return res.json();
    }

    async function updateStudent(id, student) {
        const res = await fetch(`${API}/api/students/${id}`, {
            method: 'PUT',
            headers: headers(),
            body: JSON.stringify(student)
        });
        if (!res.ok) throw new Error((await res.json()).error || 'Error actualizando alumno');
        return res.json();
    }

    async function deleteStudent(id) {
        const res = await fetch(`${API}/api/students/${id}`, {
            method: 'DELETE',
            headers: headers()
        });
        if (!res.ok) throw new Error('Error eliminando alumno');
        return res.json();
    }

    // Funciones auxiliares
    function formatDate(date) {
        if (!date) return '';
        try {
            const d = new Date(date);
            const yyyy = d.getFullYear();
            const mm = String(d.getMonth() + 1).padStart(2, '0');
            const dd = String(d.getDate()).padStart(2, '0');
            return `${yyyy}-${mm}-${dd}`;
        } catch (e) {
            return '';
        }
    }

    window.adminStudents = {
        listStudents,
        createStudent,
        updateStudent,
        deleteStudent,
        formatDate
    };
})();