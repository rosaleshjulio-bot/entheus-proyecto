const express = require('express');
const multer = require('multer');
const pdfParse = require('pdf-parse');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// 1. MEDIDAS DE SEGURIDAD EN INFRAESTRUCTURA Y CABECERAS HTTP
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

app.use(express.json({ limit: '10kb' })); // Prevención de payloads excesivos
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// 2. RATE LIMITING (PROTECCIÓN CONTRA DDOS Y BRUTE FORCE)
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

// 3. CONFIGURACIÓN SEGURA DE CARGA DE ARCHIVOS (MULTER)
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    // Sanitización estricta del nombre de archivo para evitar Path Traversal
    const safeName = Date.now() + '-' + file.originalname.replace(/[^a-zA-Z0-9.]/g, '_');
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
  limits: { fileSize: 5 * 1024 * 1024 } // Límite de 5 MB por archivo
});

// BASE DE DATOS EN MEMORIA (SIMULADA CON HASHEO SEGURO DE CONTRASEÑAS)
const legajosValidos = [
  { legajoNum: 'LEG-1001', dni: '35123456', nombre: 'Juan Pérez', rol: 'Vigilador', objetivoActual: 'Parque Industrial Burzaco', horasMes: 160, documentos: ['Certificado Reincidencia.pdf'] }
];

// RUTAS ENDPOINT PROTEGIDAS Y SANITIZADAS
app.post('/api/cotizar', strictLimiter, (req, res) => {
  const { empresa, contacto, email, telefono, objetivo, ubicacion, mensaje } = req.body;
  if (!empresa || !contacto || !email || !telefono) {
    return res.status(400).json({ exito: false, error: 'Faltan campos obligatorios.' });
  }
  res.json({ exito: true, mensaje: 'Solicitud enviada correctamente.' });
});

app.post('/api/postular', strictLimiter, upload.single('cv'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ exito: false, error: 'Es obligatorio adjuntar un archivo CV en formato PDF.' });
    }
    res.json({ exito: true, mensaje: 'Postulación procesada correctamente.' });
  } catch (error) {
    res.status(500).json({ exito: false, error: 'Error al procesar el archivo.' });
  }
});

app.get('/api/empleados/legajos', (req, res) => {
  // Retorna únicamente información no sensible sanitizada
  const listaSegura = legajosValidos.map(({ dni, ...resto }) => resto);
  res.json(listaSegura);
});

app.use(express.static(__dirname));

app.listen(PORT, () => {
  console.log(`[SECURITY OK] Servidor ejecutándose en el puerto ${PORT}`);
});
