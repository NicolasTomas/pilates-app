// admin_classes.js - gestión básica de clases
(function () {
    const API = '';
    function headers() {
        const t = localStorage.getItem('token');
        return { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' };
    }

    async function listClasses() {
        const res = await fetch(`${API}/api/classes`, { headers: headers() });
        if (!res.ok) throw new Error('Error listando clases');
        return res.json();
    }

    async function createClass(payload) {
        const res = await fetch(`${API}/api/classes`, { method: 'POST', headers: headers(), body: JSON.stringify(payload) });
        if (!res.ok) throw new Error((await res.json()).error || 'Error creando clase');
        return res.json();
    }

    async function updateClass(id, payload) {
        const res = await fetch(`${API}/api/classes/${id}`, { method: 'PUT', headers: headers(), body: JSON.stringify(payload) });
        if (!res.ok) throw new Error((await res.json()).error || 'Error actualizando clase');
        return res.json();
    }

    async function deleteClass(id) {
        const res = await fetch(`${API}/api/classes/${id}`, { method: 'DELETE', headers: headers() });
        if (!res.ok) throw new Error('Error eliminando clase');
        return res.json();
    }

    async function getClassStudents(id) {
        const res = await fetch(`${API}/api/classes/${id}/students`, { headers: headers() });
        if (!res.ok) throw new Error('Error obteniendo estudiantes');
        return res.json();
    }

    async function addStudent(classId, studentId) {
        const res = await fetch(`${API}/api/classes/${classId}/students`, {
            method: 'POST',
            headers: headers(),
            body: JSON.stringify({ studentId })
        });
        if (!res.ok) throw new Error((await res.json()).error || 'Error inscribiendo estudiante');
        return res.json();
    }

    async function removeStudent(classId, studentId) {
        const res = await fetch(`${API}/api/classes/${classId}/students/${studentId}`, {
            method: 'DELETE',
            headers: headers()
        });
        if (!res.ok) throw new Error((await res.json()).error || 'Error dando de baja estudiante');
        return res.json();
    }

    // Cancel a class for a student (creates a ticket) - can be called by student or admin
    async function cancelClassForStudent(classId, studentId) {
        const res = await fetch(`${API}/api/students/${studentId}/cancel/${classId}`, {
            method: 'POST',
            headers: headers()
        });
        if (!res.ok) throw new Error((await res.json()).error || 'Error cancelando clase');
        return res.json();
    }

    // Recover a class for a student using a ticketId
    async function recoverClassForStudent(classId, studentId, ticketId) {
        const res = await fetch(`${API}/api/students/${studentId}/recover/${classId}`, {
            method: 'POST',
            headers: headers(),
            body: JSON.stringify({ ticketId })
        });
        if (!res.ok) throw new Error((await res.json()).error || 'Error recuperando clase');
        return res.json();
    }

    window.adminClasses = {
        listClasses, createClass, updateClass, deleteClass,
        getClassStudents, addStudent, removeStudent
        , cancelClassForStudent, recoverClassForStudent
    };
})();
