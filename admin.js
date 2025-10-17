// admin.js
import {
  app,            // <- necesitamos app para clonar la config en la app secundaria
  auth,
  db,
  signOut,
  doc,
  getDoc,
  setDoc,
  updateDoc,
  deleteDoc,
  collection,
  query,
  where,
  getDocs,
} from "./firebase.js";

// Para crear usuarios sin desloguear al admin usamos una app secundaria:
import { initializeApp as initSecondaryApp } from "https://www.gstatic.com/firebasejs/10.7.1/firebase-app.js";
import { getAuth as getSecondaryAuth, createUserWithEmailAndPassword } from "https://www.gstatic.com/firebasejs/10.7.1/firebase-auth.js";

document.addEventListener("DOMContentLoaded", () => {
  /* ==============================
     ELEMENTOS Y UTILIDADES
  ============================== */
  const alertBox = document.getElementById("alert");
  const tabs = document.querySelectorAll(".tab");
  const sections = document.querySelectorAll("main section");
  const logoutBtn = document.getElementById("logoutBtn");

  // Rooms
  const roomName = document.getElementById("roomName");
  const roomCapacity = document.getElementById("roomCapacity");
  const createRoomBtn = document.getElementById("createRoomBtn");
  const roomsTable = document.getElementById("roomsTable");

  // Classes
  const classDays = document.getElementById("classDays");
  const classTime = document.getElementById("classTime");
  const classRoom = document.getElementById("classRoom");
  const classTeacher = document.getElementById("classTeacher");
  const createClassBtn = document.getElementById("createClassBtn");
  const classesTable = document.getElementById("classesTable");

  // Users (crear alumno/profesor)
  const userRole = document.getElementById("userRole");
  const userFirst = document.getElementById("userFirst");
  const userLast = document.getElementById("userLast");
  const userDNI = document.getElementById("userDNI");
  const userPhone = document.getElementById("userPhone");
  const userEmergency = document.getElementById("userEmergency");
  const createUserBtn = document.getElementById("createUserBtn");

  // Listados
  const studentsTable = document.getElementById("studentsTable");
  const teachersTable = document.getElementById("teachersTable");

  // Settings
  const gymName = document.getElementById("gymName");
  const gymAddress = document.getElementById("gymAddress");
  const gymPhone = document.getElementById("gymPhone");
  const saveGymBtn = document.getElementById("saveGymBtn");

  let currentUser = null;

  function showAlert(msg, type = "error") {
    alertBox.textContent = msg;
    alertBox.className = "alert " + (type === "success" ? "alert-success" : "alert-error");
    alertBox.style.display = "block";
    setTimeout(() => (alertBox.style.display = "none"), 3500);
  }

  const generateId = (prefix) =>
    `${prefix}_${Math.random().toString(36).slice(2, 9)}${Date.now().toString(36)}`;

  /* ==============================
     INICIALIZACIÓN
  ============================== */
  async function init() {
    await validateSession();   // asegura usuario admin y carga datos base
    setupTabs();               // engancha los tabs cuando el DOM ya está
    setupLogout();             // botón salir
    wireActions();             // listeners de botones crear/guardar
    delegateTableActions();    // listeners delegados para eliminar
  }

  async function validateSession() {
    const saved = localStorage.getItem("currentUser");
    if (!saved) {
      window.location.href = "./index.html";
      return;
    }
    currentUser = JSON.parse(saved);
    if (!currentUser?.role || currentUser.role.toLowerCase() !== "administrador") {
      showAlert("⚠️ Acceso denegado. No sos administrador.");
      setTimeout(() => (window.location.href = "./index.html"), 1200);
      return;
    }
    await loadInitialData();
  }

  /* ==============================
     NAVEGACIÓN ENTRE TABS
  ============================== */
  function setupTabs() {
    tabs.forEach((tab) => {
      tab.addEventListener("click", () => {
        tabs.forEach((t) => t.classList.remove("active"));
        sections.forEach((s) => s.classList.remove("active"));

        tab.classList.add("active");
        const id = tab.getAttribute("data-target");
        const target = document.getElementById(id);
        if (target) target.classList.add("active");
        window.scrollTo({ top: 0, behavior: "smooth" });
      });
    });
  }

  function setupLogout() {
    logoutBtn.addEventListener("click", async () => {
      await signOut(auth);
      localStorage.clear();
      window.location.href = "./index.html";
    });
  }

  /* ==============================
     WIRE ACTIONS (crear/guardar)
  ============================== */
  function wireActions() {
    createRoomBtn?.addEventListener("click", createRoom);
    createClassBtn?.addEventListener("click", createClass);
    createUserBtn?.addEventListener("click", createUser);
    saveGymBtn?.addEventListener("click", saveGymInfo);
  }

  function delegateTableActions() {
    document.body.addEventListener("click", async (e) => {
      const btn = e.target.closest("button");
      if (!btn) return;
      const { action, id } = btn.dataset;

      try {
        if (action === "deleteRoom" && id) {
          if (!confirm("¿Eliminar este salón?")) return;
          await deleteDoc(doc(db, "rooms", id));
          showAlert("✅ Salón eliminado", "success");
          await loadRooms();
          await loadRoomAndTeacherOptions();
        }

        if (action === "deleteClass" && id) {
          if (!confirm("¿Eliminar esta clase?")) return;
          await deleteDoc(doc(db, "classes", id));
          showAlert("✅ Clase eliminada", "success");
          await loadClasses();
        }

        if (action === "deleteStudent" && id) {
          if (!confirm("¿Eliminar este alumno?")) return;
          await deleteDoc(doc(db, "users", id));
          showAlert("✅ Alumno eliminado", "success");
          await loadStudents();
        }

        if (action === "deleteTeacher" && id) {
          if (!confirm("¿Eliminar este profesor?")) return;
          await deleteDoc(doc(db, "users", id));
          showAlert("✅ Profesor eliminado", "success");
          await loadTeachers();
          await loadRoomAndTeacherOptions();
        }
      } catch (err) {
        console.error(err);
        showAlert("❌ Ocurrió un error al ejecutar la acción.");
      }
    });
  }

  /* ==============================
     SALONES
  ============================== */
  async function createRoom() {
    const name = roomName.value.trim();
    const capacity = parseInt(roomCapacity.value, 10);
    if (!name || !capacity || capacity < 1) {
      showAlert("⚠️ Completá correctamente nombre y capacidad.");
      return;
    }
    try {
      const id = generateId("room");
      await setDoc(doc(db, "rooms", id), {
        name,
        capacity,
        gymId: currentUser.gymId,
        createdAt: new Date().toISOString(),
      });
      roomName.value = "";
      roomCapacity.value = "";
      showAlert("✅ Salón creado", "success");
      await loadRooms();
      await loadRoomAndTeacherOptions();
    } catch (e) {
      console.error(e);
      showAlert("❌ Error al crear salón.");
    }
  }

  async function loadRooms() {
    roomsTable.innerHTML = "";
    const qRooms = query(collection(db, "rooms"), where("gymId", "==", currentUser.gymId));
    const snap = await getDocs(qRooms);
    if (snap.empty) {
      roomsTable.innerHTML = `<tr><td colspan="3" style="text-align:center;">Sin salones</td></tr>`;
      return;
    }
    snap.forEach((r) => {
      const data = r.data();
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${data.name}</td>
        <td>${data.capacity}</td>
        <td>
          <button class="btn" data-action="deleteRoom" data-id="${r.id}">Eliminar</button>
        </td>`;
      roomsTable.appendChild(tr);
    });
  }

  /* ==============================
     CLASES
  ============================== */
  async function createClass() {
    const daysStr = classDays.value.trim();
    const time = classTime.value;
    const roomId = classRoom.value;
    const teacherId = classTeacher.value || null;

    if (!daysStr || !time || !roomId) {
      showAlert("⚠️ Completá días, horario y salón.");
      return;
    }
    try {
      const id = generateId("class");
      await setDoc(doc(db, "classes", id), {
        days: daysStr.split(",").map((d) => d.trim()).filter(Boolean),
        time,
        roomId,
        teacherId,
        gymId: currentUser.gymId,
        createdAt: new Date().toISOString(),
      });
      classDays.value = "";
      classTime.value = "";
      showAlert("✅ Clase creada", "success");
      await loadClasses();
    } catch (e) {
      console.error(e);
      showAlert("❌ Error al crear clase.");
    }
  }

  async function loadClasses() {
    classesTable.innerHTML = "";
    const qClasses = query(collection(db, "classes"), where("gymId", "==", currentUser.gymId));
    const snap = await getDocs(qClasses);
    if (snap.empty) {
      classesTable.innerHTML = `<tr><td colspan="5" style="text-align:center;">No hay clases</td></tr>`;
      return;
    }

    for (const d of snap.docs) {
      const c = d.data();
      let roomNameTxt = "—";
      let teacherNameTxt = "—";

      if (c.roomId) {
        const rDoc = await getDoc(doc(db, "rooms", c.roomId));
        if (rDoc.exists()) roomNameTxt = rDoc.data().name || "—";
      }
      if (c.teacherId) {
        const tDoc = await getDoc(doc(db, "users", c.teacherId));
        if (tDoc.exists()) teacherNameTxt = tDoc.data().name || "—";
      }

      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${(c.days || []).join(", ")}</td>
        <td>${c.time || "—"}</td>
        <td>${roomNameTxt}</td>
        <td>${teacherNameTxt}</td>
        <td>
          <button class="btn" data-action="deleteClass" data-id="${d.id}">Eliminar</button>
        </td>`;
      classesTable.appendChild(tr);
    }
  }

  async function loadRoomAndTeacherOptions() {
    // Salones
    classRoom.innerHTML = "";
    const qRooms = query(collection(db, "rooms"), where("gymId", "==", currentUser.gymId));
    const roomsSnap = await getDocs(qRooms);
    classRoom.innerHTML = roomsSnap.empty
      ? `<option value="">⚠️ No hay salones</option>`
      : `<option value="">Seleccionar salón</option>`;
    roomsSnap.forEach((r) => {
      classRoom.innerHTML += `<option value="${r.id}">${r.data().name}</option>`;
    });

    // Profesores
    classTeacher.innerHTML = "";
    const qTeachers = query(
      collection(db, "users"),
      where("gymId", "==", currentUser.gymId),
      where("role", "==", "profesor")
    );
    const teachersSnap = await getDocs(qTeachers);
    classTeacher.innerHTML = teachersSnap.empty
      ? `<option value="">⚠️ No hay profesores</option>`
      : `<option value="">Seleccionar profesor</option>`;
    teachersSnap.forEach((t) => {
      classTeacher.innerHTML += `<option value="${t.id}">${t.data().name}</option>`;
    });
  }

  /* ==============================
     CREAR USUARIO (ALUMNO/PROFESOR)
     - Crea documento en "users"
     - Crea CUENTA en Firebase Auth usando app secundaria
  ============================== */
  async function createUser() {
    const role = (userRole.value || "").toLowerCase();
    const first = userFirst.value.trim();
    const last = userLast.value.trim();
    const dni = userDNI.value.trim();
    const phone = userPhone.value.trim();
    const emergency = userEmergency.value.trim();

    if (!first || !last || !dni || !phone || !emergency) {
      showAlert("⚠️ Completá todos los campos.");
      return;
    }
    if (!/^[0-9]+$/.test(dni)) {
      showAlert("⚠️ El DNI debe tener solo números.");
      return;
    }

    try {
      // Evitar duplicados de DNI
      const qDni = query(collection(db, "users"), where("dni", "==", dni));
      const snapDni = await getDocs(qDni);
      if (!snapDni.empty) {
        showAlert("⚠️ Ya existe un usuario con ese DNI.");
        return;
      }

      // 1) Crear cuenta Auth en app secundaria
      const secApp = initSecondaryApp(app.options, `sec_${Date.now()}`);
      const secAuth = getSecondaryAuth(secApp);

      const fakeEmail = `${dni}@fakeuser.com`;
      const password = dni; // simple: DNI como clave
      const cred = await createUserWithEmailAndPassword(secAuth, fakeEmail, password);
      const uid = cred.user.uid;

      // 2) Crear documento Firestore
      const userData = {
        name: `${first} ${last}`,
        firstName: first,
        lastName: last,
        dni,
        phone,
        emergency,
        email: fakeEmail,
        role, // "alumno" | "profesor"
        gymId: currentUser.gymId,
        createdAt: new Date().toISOString(),
      };
      await setDoc(doc(db, "users", uid), userData);

      // 3) Feedback + limpieza
      showAlert(`✅ ${role === "profesor" ? "Profesor" : "Alumno"} creado`, "success");
      userFirst.value = "";
      userLast.value = "";
      userDNI.value = "";
      userPhone.value = "";
      userEmergency.value = "";

      // 4) Refrescar listados y selects
      if (role === "profesor") {
        await loadTeachers();
        await loadRoomAndTeacherOptions();
      } else {
        await loadStudents();
      }
    } catch (e) {
      console.error(e);
      showAlert("❌ No se pudo crear el usuario.");
    }
  }

  /* ==============================
     ALUMNOS
  ============================== */
  async function loadStudents() {
    studentsTable.innerHTML = "";
    const qSt = query(
      collection(db, "users"),
      where("gymId", "==", currentUser.gymId),
      where("role", "==", "alumno")
    );
    const snap = await getDocs(qSt);
    if (snap.empty) {
      studentsTable.innerHTML = `<tr><td colspan="6" style="text-align:center;">Sin alumnos</td></tr>`;
      return;
    }
    snap.forEach((d) => {
      const s = d.data();
      // Partimos el nombre para columnas
      const [first = "—", last = ""] = (s.name || "—").split(" ");
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${first}</td>
        <td>${last}</td>
        <td>${s.dni || "—"}</td>
        <td>${s.phone || "—"}</td>
        <td>${s.emergency || "—"}</td>
        <td>
          <button class="btn" data-action="deleteStudent" data-id="${d.id}">Eliminar</button>
        </td>`;
      studentsTable.appendChild(tr);
    });
  }

  /* ==============================
     PROFESORES
  ============================== */
  async function loadTeachers() {
    teachersTable.innerHTML = "";
    const qTc = query(
      collection(db, "users"),
      where("gymId", "==", currentUser.gymId),
      where("role", "==", "profesor")
    );
    const snap = await getDocs(qTc);
    if (snap.empty) {
      teachersTable.innerHTML = `<tr><td colspan="5" style="text-align:center;">Sin profesores</td></tr>`;
      return;
    }
    snap.forEach((d) => {
      const p = d.data();
      const [first = "—", last = ""] = (p.name || "—").split(" ");
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${first}</td>
        <td>${last}</td>
        <td>${p.dni || "—"}</td>
        <td>${p.phone || "—"}</td>
        <td>
          <button class="btn" data-action="deleteTeacher" data-id="${d.id}">Eliminar</button>
        </td>`;
      teachersTable.appendChild(tr);
    });
  }

  /* ==============================
     CONFIGURACIÓN DEL GIMNASIO
  ============================== */
  async function loadGymInfo() {
    try {
      const gDoc = await getDoc(doc(db, "gyms", currentUser.gymId));
      if (gDoc.exists()) {
        const g = gDoc.data();
        gymName.value = g.name || "";
        gymAddress.value = g.address || "";
        gymPhone.value = g.phone || "";
      }
    } catch (e) {
      console.error(e);
    }
  }

  async function saveGymInfo() {
    const name = gymName.value.trim();
    const address = gymAddress.value.trim();
    const phone = gymPhone.value.trim();
    if (!name) {
      showAlert("⚠️ El nombre del gimnasio es obligatorio.");
      return;
    }
    try {
      await updateDoc(doc(db, "gyms", currentUser.gymId), {
        name,
        address,
        phone,
        updatedAt: new Date().toISOString(),
      });
      showAlert("✅ Información guardada", "success");
    } catch (e) {
      console.error(e);
      showAlert("❌ Error al guardar la información.");
    }
  }

  /* ==============================
     CARGA INICIAL
  ============================== */
  async function loadInitialData() {
    await loadRooms();
    await loadTeachers();
    await loadStudents();
    await loadClasses();
    await loadGymInfo();
    await loadRoomAndTeacherOptions();
  }

  // GO!
  init();
});
