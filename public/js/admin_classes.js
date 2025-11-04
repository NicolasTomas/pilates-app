// admin_classes.js - gestión básica de clases
(function () {
    const API = '';
    function headers() {
        const t = localStorage.getItem('token');
        return { Authorization: `Bearer ${t}`, 'Content-Type': 'application/json' };
    }

    async function listClasses() {
        // If we detect via local storage that caller is a professor, skip the
        // admin endpoint to avoid generating 403s in the network tab and
        // directly call the public open endpoint.
        const role = localStorage.getItem('role');
        if (role === 'profesor') {
            const resOpen = await fetch(`${API}/api/classes/open`, { headers: headers() });
            if (!resOpen.ok) throw new Error('Error listando clases');
            return resOpen.json();
        }

        // Otherwise try admin endpoint first, then fall back to open if forbidden.
        const res = await fetch(`${API}/api/classes`, { headers: headers() });
        if (res.ok) return res.json();
        if (res.status === 401 || res.status === 403) {
            const res2 = await fetch(`${API}/api/classes/open`, { headers: headers() });
            if (!res2.ok) throw new Error('Error listando clases');
            return res2.json();
        }
        throw new Error('Error listando clases');
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

    // Assign or unassign a professor to a class without sending full class payload
    async function assignProfessor(classId, professorId) {
        const res = await fetch(`${API}/api/classes/${classId}/assign-professor`, {
            method: 'POST',
            headers: headers(),
            body: JSON.stringify({ professorId })
        });
        if (!res.ok) throw new Error((await res.json()).error || 'Error asignando profesor a clase');
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
        , assignProfessor
    };
})();
