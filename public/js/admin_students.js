// admin_students.js - gestión de alumnos
(function () {
    const API = '';
    function headers() {
        const t = localStorage.getItem('token');
        return { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' };
    }

    async function listStudents(search = '') {
        const res = await fetch(`${API}/api/users?role=alumno${search ? `&search=${search}` : ''}`, {
            headers: headers()
        });
        if (!res.ok) throw new Error('Error listando alumnos');
        return res.json();
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
        return new Date(date).toISOString().split('T')[0];
    }

    window.adminStudents = {
        listStudents,
        createStudent,
        updateStudent,
        deleteStudent,
        formatDate
    };
})();