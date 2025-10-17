// auth.js
import {
  auth,
  db,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  doc,
  getDoc,
} from "./firebase.js";

// === ELEMENTOS DEL DOM ===
const dniLoginForm = document.getElementById("dniLoginForm");
const adminBtn = document.getElementById("adminBtn");
const adminModal = document.getElementById("adminModal");
const closeAdminModal = document.getElementById("closeAdminModal");
const adminLoginForm = document.getElementById("adminLoginForm");
const alertBox = document.getElementById("alert");

// === FUNCIONES ===
function showAlert(message, type = "error") {
  alertBox.textContent = message;
  alertBox.className = "alert " + (type === "success" ? "alert-success" : "alert-error");
  alertBox.style.display = "block";
  setTimeout(() => (alertBox.style.display = "none"), 4000);
}

// === MODAL ADMINISTRADOR ===
adminBtn.addEventListener("click", () => {
  adminModal.style.display = "flex";
});
closeAdminModal.addEventListener("click", () => {
  adminModal.style.display = "none";
});
window.addEventListener("click", (e) => {
  if (e.target === adminModal) adminModal.style.display = "none";
});

// === LOGIN POR DNI (alumnos y profesores) ===
dniLoginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const dni = document.getElementById("dniLogin").value.trim();

  if (!/^[0-9]+$/.test(dni)) {
    showAlert("❌ El DNI debe contener solo números");
    return;
  }

  const fakeEmail = `${dni}@fakeuser.com`;
  const password = dni;

  try {
    const userCredential = await signInWithEmailAndPassword(auth, fakeEmail, password);
    const user = userCredential.user;

    // Buscar datos en Firestore
    const userDoc = await getDoc(doc(db, "users", user.uid));
    if (!userDoc.exists()) {
      showAlert("❌ No se encontraron datos del usuario");
      await signOut(auth);
      return;
    }

    const userData = userDoc.data();
    handleRedirectByRole(userData);

  } catch (error) {
    console.error("Error al ingresar con DNI:", error);
    if (error.code === "auth/user-not-found") {
      showAlert("❌ No existe una cuenta con ese DNI");
    } else if (error.code === "auth/invalid-credential") {
      showAlert("❌ Credencial inválida");
    } else {
      showAlert("❌ Error al iniciar sesión");
    }
  }
});

// === LOGIN ADMINISTRADOR ===
adminLoginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = document.getElementById("adminEmailLogin").value.trim();
  const password = document.getElementById("adminPasswordLogin").value.trim();

  try {
    const userCredential = await signInWithEmailAndPassword(auth, email, password);
    const user = userCredential.user;

    const userDoc = await getDoc(doc(db, "users", user.uid));
    if (!userDoc.exists()) {
      showAlert("❌ Usuario no encontrado");
      await signOut(auth);
      return;
    }

    const userData = userDoc.data();
    handleRedirectByRole(userData);
  } catch (error) {
    console.error("Error en login de administrador:", error);
    showAlert("❌ Correo o contraseña incorrectos");
  }
});

// === REDIRECCIÓN SEGÚN ROL ===
function handleRedirectByRole(userData) {
  const role = userData.role?.toLowerCase();
  if (!role) {
    showAlert("❌ No se detectó el rol del usuario");
    return;
  }

  // Guardar los datos básicos por si los necesitan otras páginas
  localStorage.setItem("currentUser", JSON.stringify(userData));

  switch (role) {
    case "alumno":
      window.location.href = "./alumno.html";
      break;
    case "profesor":
      window.location.href = "./profesor.html";
      break;
    case "administrador":
      window.location.href = "./admin.html";
      break;
    case "superusuario":
      window.location.href = "./superuser.html";
      break;
    default:
      showAlert("❌ Rol desconocido. Contactá con el administrador.");
  }
}

// === MANTENER SESIÓN ===
onAuthStateChanged(auth, async (user) => {
  if (user) {
    const userDoc = await getDoc(doc(db, "users", user.uid));
    if (userDoc.exists()) {
      const userData = userDoc.data();
      handleRedirectByRole(userData);
    }
  }
});
