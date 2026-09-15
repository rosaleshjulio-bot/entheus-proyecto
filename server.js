const express = require('express');
const multer = require('multer');
const pdfParse = require('pdf-parse');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const fs = require('fs');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// 1. MEDIDAS DE SEGURIDAD Y CONFIGURACIÓN INICIAL
// ==========================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Configuración de sesiones optimizada para producción
app.use(session({
    secret: process.env.SESSION_SECRET || 'entheus_clave_secreta_segura_2026',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production', 
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 
    }
}));

// Servir archivos estáticos desde la carpeta 'public' (index.html, etc.)
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// 2. RATE LIMITING (PROTECCIÓN CONTRA ATAQUES)
// ==========================================
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { exito: false, error: 'Demasiadas peticiones desde esta IP. Intente más tarde.' }
});

const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { exito: false, error: 'Límite de intentos excedido. Por favor espere 15 minutos.' }
});

app.use(globalLimiter);

// ==========================================
// 3. CONFIGURACIÓN DE CARGA DE ARCHIVOS (MULTER)
// ==========================================
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const safeName = Date.now() + '-' + file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, safeName);
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype === 'application/pdf') {
    cb(null, true);
  } else {
    cb(new Error('Formato no permitido: Únicamente se aceptan archivos PDF válidos.'), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }
});

// ==========================================
// 4. BASES DE DATOS EN MEMORIA Y USUARIOS DE STAFF
// ==========================================
const usuariosStaff = [
    { usuario: 'rrhh@entheus.com', passwordHash: bcrypt.hashSync('123456', 10), departamento: 'rrhh', nombre: 'Lic. Gomez' },
    { usuario: 'logistica@entheus.com', passwordHash: bcrypt.hashSync('123456', 10), departamento: 'logistica', nombre: 'Carlos Logística' },
    { usuario: 'operaciones@entheus.com', passwordHash: bcrypt.hashSync('123456', 10), departamento: 'operaciones', nombre: 'Ana Operaciones' },
    { usuario: 'admin@entheus.com', passwordHash: bcrypt.hashSync('123456', 10), departamento: 'admin', nombre: 'Super Admin' }
];

let legajosValidos = [
  { legajoNum: 'LEG-1001', dni: '35123456', nombre: 'Juan Pérez', rol: 'Vigilador', objetivoActual: 'Parque Industrial Burzaco', horasMes: 160, documentos: [] }
];

let baseDatosCVs = [];

// ==========================================
// 5. RUTAS DE AUTENTICACIÓN Y SEGURIDAD DE SESIÓN
// ==========================================
app.post('/api/login', strictLimiter, (req, res) => {
    const { usuario, password, departamento } = req.body;

    if (!usuario || !password || !departamento) {
        return res.status(400).json({ exito: false, error: 'Todos los campos son obligatorios.' });
    }

    const userFound = usuariosStaff.find(u => u.usuario === usuario && u.departamento === departamento);

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

// Middleware de protección estricta
function verificarSesion(req, res, next) {
    if (req.session && req.session.user) {
        return next();
    }
    return res.status(403).sendFile(path.join(__dirname, 'public', 'index.html'));
}

// Ruta protegida del panel (admin.html en la raíz)
app.get('/admin.html', verificarSesion, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// Ruta para destruir sesión (Logout)
app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ exito: false, error: 'No se pudo cerrar la sesión.' });
        }
        res.clearCookie('connect.sid');
        res.json({ exito: true, mensaje: 'Sesión cerrada correctamente.' });
    });
});

// ==========================================
// 6. ENDPOINTS PÚBLICOS Y DE GESTIÓN
// ==========================================
app.post('/api/cotizar', strictLimiter, (req, res) => {
  const { empresa, contacto, email, telefono } = req.body;
  if (!empresa || !contacto || !email || !telefono) {
    return res.status(400).json({ exito: false, error: 'Faltan campos obligatorios.' });
  }
  res.json({ exito: true, mensaje: 'Solicitud enviada correctamente.' });
});

app.post('/api/postular', strictLimiter, upload.single('cvArchivo'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ exito: false, error: 'Es obligatorio adjuntar un archivo CV en formato PDF.' });
    }

    const { nombreCandidato, dniCandidato, puestoCandidato } = req.body;

    const nuevaPostulacion = {
      fecha: new Date().toLocaleDateString(),
      nombre: nombreCandidato || 'Sin nombre',
      dni: dniCandidato || 'Sin DNI',
      puesto: puestoCandidato || 'No especificado',
      archivo: req.file.filename,
      estado: 'Pendiente'
    };

    baseDatosCVs.unshift(nuevaPostulacion);
    res.json({ exito: true, mensaje: 'Postulación procesada correctamente.' });
  } catch (error) {
    res.status(500).json({ exito: false, error: 'Error al procesar el archivo.' });
  }
});

app.get('/api/postulaciones', verificarSesion, (req, res) => {
  res.json(baseDatosCVs);
});

app.get('/api/empleados/legajos', verificarSesion, (req, res) => {
  res.json(legajosValidos);
});

app.post('/api/empleados/alta', strictLimiter, verificarSesion, (req, res) => {
  const { legajoNum, dni, nombre, rol, objetivoActual } = req.body;
  if (!legajoNum || !dni || !nombre || !rol) {
    return res.status(400).json({ exito: false, error: 'Faltan datos obligatorios.' });
  }

  const existe = legajosValidos.find(e => e.legajoNum === legajoNum);
  if (existe) {
    return res.status(400).json({ exito: false, error: 'El número de legajo ya se encuentra registrado.' });
  }

  legajosValidos.push({
    legajoNum,
    dni,
    nombre,
    rol,
    objetivoActual: objetivoActual || 'Sin asignar',
    horasMes: 0,
    documentos: []
  });

  res.json({ exito: true, mensaje: `Personal ${nombre} (${rol}) dado de alta con éxito.` });
});

app.post('/api/empleados/subir-masivo', strictLimiter, verificarSesion, upload.array('documentosPDF', 50), (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ exito: false, error: 'No se adjuntaron archivos PDF.' });
    }

    let asignadosCount = 0;
    let noAsignados = [];

    req.files.forEach(file => {
      const empleadoEncontrado = legajosValidos.find(emp => file.originalname.includes(emp.legajoNum));
      if (empleadoEncontrado) {
        empleadoEncontrado.documentos.push(file.filename);
        asignadosCount++;
      } else {
        noAsignados.push(file.originalname);
      }
    });

    res.json({ 
      exito: true, 
      mensaje: `Proceso exitoso: Se vincularon ${asignadosCount} recibos.${noAsignados.length > 0 ? ' No vinculados: ' + noAsignados.join(', ') : ''}` 
    });
  } catch (error) {
    res.status(500).json({ exito: false, error: 'Error al procesar la carga masiva.' });
  }
});

// ==========================================
// 7. INICIO DEL SERVIDOR
// ==========================================
app.listen(PORT, () => {
  console.log(`[SECURITY & SERVER OK] Servidor ejecutándose en el puerto ${PORT}`);
});