# Pilates Camilla - Proyecto básico

Proyecto demo: frontend en HTML/CSS/JS vanilla y backend en Node/Express con MongoDB.

Características:
- Login por DNI (sin contraseña) y redirección por rol.
- Roles: alumno, profesor, administrador, superusuario.
- JWT almacenado en localStorage para autenticación en frontend.

Requisitos:
- Node.js 18+ y npm
- MongoDB corriendo localmente o URL en MONGO_URI

Pasos (PowerShell):

1. Copiar variables de entorno:

```powershell
cp .env.example .env
notepad .env  # editar si hace falta
```

2. Instalar dependencias:

```powershell
npm install
```

3. Cargar datos de prueba:

```powershell
npm run seed
```

4. Ejecutar servidor:

```powershell
npm start
```

5. Abrir en el navegador: http://localhost:3000/index.html

Archivos importantes:
- `server.js` - servidor Express y API
- `seed.js` - datos de prueba
- `public/js/auth.js` - funciones de autenticación cliente
- `index.html`, `alumno.html`, `profesor.html`, `administrador.html`, `superusuario.html` - vistas

Próximos pasos posibles:
- Implementar CRUD para clases y reservas (API + UI)
- Añadir contraseñas y recuperación
- Validaciones y tests
