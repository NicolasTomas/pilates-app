// firebase.js
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.7.1/firebase-app.js";
import {
  getAuth,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
} from "https://www.gstatic.com/firebasejs/10.7.1/firebase-auth.js";
import {
  getFirestore,
  doc,
  getDoc,
  setDoc,
  updateDoc,
  collection,
  query,
  where,
  getDocs,
  deleteDoc
} from "https://www.gstatic.com/firebasejs/10.7.1/firebase-firestore.js";

// 🔹 Configuración del proyecto Firebase
const firebaseConfig = {
  apiKey: "AIzaSyBsc8nA2HnXp_j2_gt0X-xbrgmZd4Fqtfc",
  authDomain: "pilates-app-da715.firebaseapp.com",
  projectId: "pilates-app-da715",
  storageBucket: "pilates-app-da715.appspot.com",
  messagingSenderId: "754788583826",
  appId: "1:754788583826:web:32e2ceea64f7c29f6cc5a8",
};

// 🔹 Inicializar Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

// 🔹 Exportar objetos para otros scripts
export {
  app,
  auth,
  db,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  doc,
  getDoc,
  setDoc,
  updateDoc,
  collection,
  query,
  where,
  getDocs,
  deleteDoc,
};
