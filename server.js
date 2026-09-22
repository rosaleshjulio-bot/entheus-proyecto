const express = require('express');
const multer = require('multer');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const fs = require('fs');
const session = require('express-session');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================================
// VALIDACIÓN DE CONFIGURACIÓN CRÍTICA
// ============================================================================
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.includes('entheus_clave')) {
  console.warn('⚠️  ADVERTENCIA: SESSION_SECRET no está configurado de forma segura.');
  console.warn('   Configure SESSION_SECRET en su archivo .env para producción.');
}

// ============================================================================
// 1. MEDIDAS DE SEGURIDAD Y CONFIGURACIÓN INICIAL
// ============================================================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https://unsplash.com"],
      connectSrc: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'entheus_clave_secreta_segura_2026',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

// Servir archivos públicos SOLO desde la raíz (index.html, estilos, etc.)
app.use(express.static(path.join(__dirname, '.')));

// Ruta raíz: servir index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// 2. RATE LIMITING
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { exito: false, error: 'Demasiadas peticiones desde esta IP. Intente más tarde.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { exito: false, error: 'Límite de intentos excedido. Por favor espere 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(globalLimiter);

// ============================================================================
// 3. GESTIÓN DE DIRECTORIO DE DATOS Y CARGA DE ARCHIVOS (MULTER)
// ============================================================================
const uploadDir = path.join(__dirname, 'uploads');
const dataDir = path.join(__dirname, 'data');

[uploadDir, dataDir].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    console.log(`✓ Directorio creado: ${dir}`);
  }
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}-${file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')}`;
    cb(null, uniqueName);
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype === 'application/pdf') {
    cb(null, true);
  } else {
    cb(new Error('Solo se aceptan archivos PDF válidos.'), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }
});

// ============================================================================
// 4. UTILIDADES DE PERSISTENCIA Y SEGURIDAD
// ============================================================================
const dbPath = path.join(dataDir, 'database.json');

function cargarBaseDatos() {
  if (!fs.existsSync(dbPath)) {
    return {
      usuarios: [
        { usuario: 'rrhh@entheus.com', passwordHash: bcrypt.hashSync('Cambiar123!', 10), departamento: 'rrhh', nombre: 'Lic. Gomez' },
        { usuario: 'admin@entheus.com', passwordHash: bcrypt.hashSync('Cambiar456!', 10), departamento: 'admin', nombre: 'Super Admin' }
      ],
      empleados: [
        { legajoNum: 'LEG-1001', dni: '35123456', nombre: 'Juan Pérez', rol: 'Vigilador', objetivoActual: 'Parque Industrial Burzaco', horasMes: 160, documentos: [], fechaAlta: new Date().toISOString() }
      ],
      postulaciones: [],
      cotizaciones: []
    };
  }
  try {
    return JSON.parse(fs.readFileSync(dbPath, 'utf8'));
  } catch (e) {
    console.error('Error al leer base de datos:', e.message);
    return { usuarios: [], empleados: [], postulaciones: [], cotizaciones: [] };
  }
}

function guardarBaseDatos(db) {
  try {
    fs.writeFileSync(dbPath, JSON.stringify(db, null, 2));
  } catch (e) {
    console.error('Error al guardar base de datos:', e.message);
  }
}

let db = cargarBaseDatos();

// Sanitizador HTML simple para prevenir XSS
function sanitizarHTML(texto) {
  if (!texto) return '';
  return String(texto)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ============================================================================
// 5. MIDDLEWARE DE AUTENTICACIÓN
// ============================================================================
function verificarSesion(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  return res.status(403).json({ exito: false, error: 'No autorizado. Debe iniciar sesión.' });
}

// ============================================================================
// 6. RUTAS DE AUTENTICACIÓN
// ============================================================================
app.post('/api/login', strictLimiter, (req, res) => {
  const { usuario, password, departamento } = req.body;

  if (!usuario || !password || !departamento) {
    return res.status(400).json({ exito: false, error: 'Todos los campos son obligatorios.' });
  }

  const userFound = db.usuarios.find(u => u.usuario === usuario && u.departamento === departamento);

  if (userFound && bcrypt.compareSync(password, userFound.passwordHash)) {
    req.session.user = {
      usuario: userFound.usuario,
      departamento: userFound.departamento,
      nombre: userFound.nombre
    };
    return res.json({
      exito: true,
      mensaje: 'Acceso autorizado',
      redirectUrl: '/admin.html'
    });
  } else {
    return res.status(401).json({
      exito: false,
      error: 'Credenciales incorrectas o departamento inválido.'
    });
  }
});

app.get('/admin.html', verificarSesion, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ exito: false, error: 'No se pudo cerrar la sesión.' });
    }
    res.clearCookie('connect.sid');
    res.json({ exito: true, mensaje: 'Sesión cerrada correctamente.' });
  });
});

// ============================================================================
// 7. ENDPOINTS DE GESTIÓN - POSTULACIONES
// ============================================================================
app.post('/api/postular', strictLimiter, upload.single('cvArchivo'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ exito: false, error: 'Debe adjuntar un archivo CV en formato PDF.' });
    }

    const nombreCandidato = sanitizarHTML(req.body.nombreCandidato || 'Sin nombre');
    const dniCandidato = sanitizarHTML(req.body.dniCandidato || 'Sin DNI');
    const puestoCandidato = sanitizarHTML(req.body.puestoCandidato || 'No especificado');

    if (nombreCandidato.length > 100 || dniCandidato.length > 20 || puestoCandidato.length > 50) {
      fs.unlinkSync(req.file.path); // Eliminar archivo si los datos son demasiado largos
      return res.status(400).json({ exito: false, error: 'Datos ingresados exceden los límites permitidos.' });
    }

    const nuevaPostulacion = {
      id: Date.now().toString(),
      fecha: new Date().toISOString(),
      nombre: nombreCandidato,
      dni: dniCandidato,
      puesto: puestoCandidato,
      archivo: req.file.filename,
      estado: 'Pendiente'
    };

    db.postulaciones.unshift(nuevaPostulacion);
    guardarBaseDatos(db);

    res.json({ exito: true, mensaje: 'Postulación procesada correctamente.' });
  } catch (error) {
    console.error('Error en postulación:', error);
    res.status(500).json({ exito: false, error: 'Error al procesar el archivo.' });
  }
});

app.get('/api/postulaciones', verificarSesion, (req, res) => {
  res.json(db.postulaciones);
});

// ============================================================================
// 8. ENDPOINTS DE GESTIÓN - EMPLEADOS
// ============================================================================
app.get('/api/empleados/legajos', verificarSesion, (req, res) => {
  res.json(db.empleados);
});

app.post('/api/empleados/alta', strictLimiter, verificarSesion, (req, res) => {
  const { legajoNum, dni, nombre, rol, objetivoActual } = req.body;

  if (!legajoNum || !dni || !nombre || !rol) {
    return res.status(400).json({ exito: false, error: 'Faltan datos obligatorios.' });
  }

  if (!/^\d{4}$/.test(legajoNum)) {
    return res.status(400).json({ exito: false, error: 'El legajo debe ser exactamente 4 dígitos.' });
  }

  const existe = db.empleados.find(e => e.legajoNum === legajoNum);
  if (existe) {
    return res.status(400).json({ exito: false, error: 'El número de legajo ya existe.' });
  }

  const nuevoEmpleado = {
    legajoNum,
    dni: sanitizarHTML(dni),
    nombre: sanitizarHTML(nombre),
    rol: sanitizarHTML(rol),
    objetivoActual: sanitizarHTML(objetivoActual || 'Sin asignar'),
    horasMes: 0,
    documentos: [],
    fechaAlta: new Date().toISOString()
  };

  db.empleados.push(nuevoEmpleado);
  guardarBaseDatos(db);

  res.json({ exito: true, mensaje: `Personal ${nombre} dado de alta con éxito.` });
});

app.delete('/api/empleados/baja/:legajoNum', verificarSesion, (req, res) => {
  const { legajoNum } = req.params;
  const index = db.empleados.findIndex(emp => emp.legajoNum === legajoNum);

  if (index === -1) {
    return res.status(404).json({ exito: false, error: 'No se encontró el legajo indicado.' });
  }

  const [baja] = db.empleados.splice(index, 1);
  guardarBaseDatos(db);

  return res.json({
    exito: true,
    mensaje: `Se dio de baja al legajo ${baja.legajoNum} (${baja.nombre}).`
  });
});

app.post('/api/empleados/subir-masivo', strictLimiter, verificarSesion, upload.array('documentosPDF', 50), (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ exito: false, error: 'No se adjuntaron archivos.' });
    }

    let asignadosCount = 0;
    let noAsignados = [];

    req.files.forEach(file => {
      const empleadoEncontrado = db.empleados.find(emp => file.originalname.includes(emp.legajoNum));
      if (empleadoEncontrado) {
        empleadoEncontrado.documentos.push(file.filename);
        asignadosCount++;
      } else {
        noAsignados.push(file.originalname);
      }
    });

    guardarBaseDatos(db);

    res.json({
      exito: true,
      mensaje: `Exitoso: ${asignadosCount} recibos vinculados.${noAsignados.length > 0 ? ' No vinculados: ' + noAsignados.join(', ') : ''}`
    });
  } catch (error) {
    console.error('Error en carga masiva:', error);
    res.status(500).json({ exito: false, error: 'Error al procesar los archivos.' });
  }
});

// ============================================================================
// 9. ENDPOINTS DE GESTIÓN - COTIZACIONES Y CONTACTO
// ============================================================================
app.post('/api/cotizar', strictLimiter, (req, res) => {
  const { empresa, contacto, email, telefono, tipo, detalles } = req.body;

  if (!empresa || !contacto || !email || !telefono) {
    return res.status(400).json({ exito: false, error: 'Faltan campos obligatorios.' });
  }

  const nuevaCotizacion = {
    id: Date.now().toString(),
    fecha: new Date().toISOString(),
    empresa: sanitizarHTML(empresa),
    contacto: sanitizarHTML(contacto),
    email: sanitizarHTML(email),
    telefono: sanitizarHTML(telefono),
    tipo: sanitizarHTML(tipo || ''),
    detalles: sanitizarHTML(detalles || ''),
    estado: 'Pendiente'
  };

  db.cotizaciones.push(nuevaCotizacion);
  guardarBaseDatos(db);

  res.json({ exito: true, mensaje: 'Solicitud de cotización enviada correctamente.' });
});

app.get('/api/cotizaciones', verificarSesion, (req, res) => {
  res.json(db.cotizaciones);
});

// ============================================================================
// 10. MANEJO DE ERRORES
// ============================================================================
app.use((err, req, res, next) => {
  console.error('Error:', err.message);

  if (err instanceof multer.MulterError) {
    return res.status(400).json({ exito: false, error: 'Error en la carga de archivo: ' + err.message });
  }

  if (err.message && err.message.includes('Solo se aceptan archivos PDF')) {
    return res.status(400).json({ exito: false, error: err.message });
  }

  res.status(500).json({ exito: false, error: 'Error interno del servidor.' });
});

app.use((req, res) => {
  res.status(404).json({ exito: false, error: 'Ruta no encontrada.' });
});

// ============================================================================
// 11. INICIO DEL SERVIDOR
// ============================================================================
app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════╗
║     ✓ ENTHEUS SECURITY - SERVIDOR EN EJECUCIÓN         ║
║     ✓ Puerto: ${PORT}                                      ║
║     ✓ Modo: ${process.env.NODE_ENV || 'development'}                                 ║
║     ✓ Seguridad: ACTIVA                                ║
╚════════════════════════════════════════════════════════╝
  `);
  console.log('📍 Acceda a: http://localhost:' + PORT);
  console.log('⚠️  En producción configure variables en .env');
});

module.exports = app;
