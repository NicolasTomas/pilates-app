(async () => {
    try {
        const API = 'http://localhost:3000';
        // Login admin
        const login = await fetch(`${API}/api/admin/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: 'admin@pilates.local', password: 'AdminPass123!' })
        });
        if (!login.ok) return console.error('Admin login failed', await login.text());
        const jl = await login.json();
        const token = jl.token;
        console.log('Got admin token');

        // Find a class with at least one student so we test a real enrolled student
        const classesRes = await fetch(`${API}/api/classes`, { headers: { Authorization: `Bearer ${token}` } });
        if (!classesRes.ok) return console.error('Failed to list classes', await classesRes.text());
        const classes = await classesRes.json();
        const clsWithStudents = classes.find(c => Array.isArray(c.students) && c.students.length > 0);
        if (!clsWithStudents) return console.error('No class with students found to test');
        const studentId = clsWithStudents.students[0];
        // Fetch student details
        const userRes = await fetch(`${API}/api/students/${studentId}`, { headers: { Authorization: `Bearer ${token}` } });
        if (!userRes.ok) return console.error('Failed to fetch student', await userRes.text());
        const student = await userRes.json();
        console.log('Using student from class', student._id || student.id, student.name, student.lastName);

        // Update dueDate to 2025-12-30 and keep classIds as current enrolled classes
        const newDue = '2025-12-30';
        const currentClassIds = (await fetch(`${API}/api/students/${studentId}/classes`, { headers: { Authorization: `Bearer ${token}` } }).then(r => r.json())).map(c => c._id);
        const updateRes = await fetch(`${API}/api/students/${student._id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
            body: JSON.stringify({ dni: student.dni, name: student.name, lastName: student.lastName, phone: student.phone || '', emergencyContact: student.emergencyContact || '', membershipType: student.membershipType || 'mensual', dueDate: newDue, classIds: currentClassIds })
        });
        console.log('Update status', updateRes.status);
        if (!updateRes.ok) console.error('Update error', await updateRes.text());

        // Wait a bit for generation
        await new Promise(r => setTimeout(r, 1500));

        // Fetch class instances for student (with debug to show upperLimit)
        const instRes = await fetch(`${API}/api/students/${student._id}/class-instances?debug=1`, { headers: { Authorization: `Bearer ${token}` } });
        if (!instRes.ok) return console.error('Failed to get class-instances', await instRes.text());
        const instBody = await instRes.json();
        const instances = Array.isArray(instBody) ? instBody : (instBody.instances || []);
        console.log('Computed upperLimit:', instBody.upperLimit || null);
        console.log('Instances count:', instances.length);
        if (instances.length) {
            const latest = instances[instances.length - 1];
            console.log('Latest instance date:', latest.dateTime);
        }
    } catch (e) {
        console.error('Smoke test error', e);
    }
})();
