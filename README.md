# 🔒 ENTHEUS SECURITY - PLATAFORMA WEB SEGURA

Plataforma corporativa integrada para Entheus Security con:
- Portal de empleados y cotizaciones
- Panel administrativo seguro (RRHH, Logística, Operaciones)
- Gestión de postulaciones y CVs
- Autenticación con sesiones protegidas
- Almacenamiento persistente de datos

## 🚀 Instalación Rápida

```bash
# 1. Clonar repositorio
git clone https://github.com/rosaleshjulio-bot/entheus-proyecto.git
cd entheus-proyecto

# 2. Instalar dependencias
npm install

# 3. Configurar variables de entorno
cp .env.example .env
# Editar .env y cambiar SESSION_SECRET a una clave segura

# 4. Ejecutar servidor
npm start
```

## 📋 Variables de Entorno (.env)

```env
PORT=3000
NODE_ENV=development
SESSION_SECRET=tu_clave_secreta_aqui_cambiar_en_produccion
DB_PATH=./data/database.json
```

⚠️ **IMPORTANTE EN PRODUCCIÓN:**
- Cambie `SESSION_SECRET` por una cadena aleatoria segura
- Use `NODE_ENV=production`
- Configure HTTPS
- Rotale las contraseñas predeterminadas

## 🔐 Credenciales Predeterminadas

| Usuario | Contraseña | Departamento |
|---------|-----------|-------------|
| rrhh@entheus.com | Cambiar123! | RRHH |
| admin@entheus.com | Cambiar456! | Administrador |

**⚠️ CAMBIAR INMEDIATAMENTE EN PRODUCCIÓN**

## 📁 Estructura

```
├── index.html              # Sitio público
├── admin.html              # Panel administrativo
├── server.js               # Backend seguro
├── package.json            # Dependencias
├── .env.example            # Variables de ejemplo
├── .gitignore              # Exclusiones de Git
├── data/                   # Base de datos JSON (no publicar)
├── uploads/                # Archivos subidos (no publicar)
└── README.md               # Este archivo
```

## 🛡️ Medidas de Seguridad Implementadas

✅ **Criptografía**
- Contraseñas hasheadas con bcrypt
- Sesiones HTTPOnly y SameSite=Strict

✅ **Validación**
- Sanitización HTML para prevenir XSS
- Límites de tamaño en uploads (5 MB)
- Validación de tipos MIME

✅ **Rate Limiting**
- 100 requests/15min por IP (global)
- 5 intentos de login/15min (strict)

✅ **Headers de Seguridad**
- Helmet: CSP, HSTS, X-Frame-Options, etc.
- CORS restringido a mismo origen

✅ **Persistencia Segura**
- Base de datos JSON con backups automáticos
- Directorio data/ excluido de Git
- Uploads no servidos directamente

## 📊 API Endpoints

### Autenticación
- `POST /api/login` - Iniciar sesión
- `POST /api/logout` - Cerrar sesión

### Postulaciones (Público)
- `POST /api/postular` - Enviar CV (multipart/form-data)
- `GET /api/postulaciones` - Listar (requiere autenticación)

### Empleados (Admin)
- `GET /api/empleados/legajos` - Listar empleados
- `POST /api/empleados/alta` - Dar de alta
- `DELETE /api/empleados/baja/:legajoNum` - Dar de baja
- `POST /api/empleados/subir-masivo` - Cargar recibos

### Cotizaciones (Público)
- `POST /api/cotizar` - Solicitar cotización
- `GET /api/cotizaciones` - Listar (requiere autenticación)

## 🐛 Troubleshooting

### Error: "SESSION_SECRET not configured"
→ Configure `SESSION_SECRET` en `.env`

### Error: "No se puede acceder a /admin.html"
→ Inicie sesión primero en `/api/login`

### Upload falla: "Solo se aceptan PDF"
→ Verifique que el archivo sea PDF válido

### Puerto 3000 en uso
→ Cambie `PORT` en `.env` o cierre el proceso usando el puerto

## 📝 Próximos Pasos

- [ ] Migrar a base de datos SQL (PostgreSQL/MySQL)
- [ ] Implementar autenticación 2FA
- [ ] Añadir dashboard analítico
- [ ] Integrar notificaciones por email
- [ ] Deploy en Docker
- [ ] Certificado SSL/TLS en producción

## 📄 Licencia

Privado - Entheus Security

## 👨‍💼 Contacto

Para consultas técnicas: soporte@entheus.com
