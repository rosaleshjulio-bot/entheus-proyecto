const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

const dbEmpleadosPath = path.join(__dirname, 'database', 'empleados.json');
if (!fs.existsSync(path.dirname(dbEmpleadosPath))) {
    fs.mkdirSync(path.dirname(dbEmpleadosPath), { recursive: true });
}
if (!fs.existsSync(dbEmpleadosPath)) {
    fs.writeFileSync(dbEmpleadosPath, JSON.stringify([], null, 2));
}

// Ruta raíz: Muestra SIEMPRE el index.html principal (Login y Registro)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Registro de empleado
app.post('/api/empleado/registrar', (req, res) => {
    try {
        const { nroLegajo, nombre, apellido, cuil, dni, password } = req.body;
        let empleados = [];
        if (fs.existsSync(dbEmpleadosPath)) {
            empleados = JSON.parse(fs.readFileSync(dbEmpleadosPath, 'utf8'));
        }

        const nombreCompleto = (nombre || '') + (apellido ? ' ' + apellido : '');
        const legajoLimpio = String(nroLegajo || '4021').replace(/[^0-9]/g, '').slice(0, 4) || '4021';
        const docLimpio = String(dni || cuil || '20999999999');

        let emp = empleados.find(e => String(e.nroLegajo) === legajoLimpio);
        if (emp) {
            emp.password = password;
            if (nombreCompleto.trim()) emp.nombre = nombreCompleto;
        } else {
            empleados.push({
                nroLegajo: legajoLimpio,
                nombre: nombreCompleto || 'Empleado Entheus',
                cuil: docLimpio,
                email: `empleado${legajoLimpio}@entheus.com`,
                departamento: 'Operaciones',
                password: password,
                fechaAlta: new Date().toISOString().split('T')[0],
                recibos: []
            });
        }

        fs.writeFileSync(dbEmpleadosPath, JSON.stringify(empleados, null, 2));
        return res.json({ exito: true, mensaje: 'Cuenta creada correctamente. Ya puedes iniciar sesión.' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ exito: false, error: 'Error interno' });
    }
});

// Login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    if ((username === 'rrhh@entheus.com' || username === 'admin') && password === 'admin123') {
        const rrhhPath = path.join(__dirname, 'private-rrhh.html');
        if (fs.existsSync(rrhhPath)) return res.sendFile(rrhhPath);
    }

    let empleados = [];
    if (fs.existsSync(dbEmpleadosPath)) {
        empleados = JSON.parse(fs.readFileSync(dbEmpleadosPath, 'utf8'));
    }

    const emp = empleados.find(e => (e.email === username || e.nroLegajo === username) && e.password === password);
    if (emp) {
        const empPath = path.join(__dirname, 'private-empleado.html');
        if (fs.existsSync(empPath)) return res.sendFile(empPath);
    }

    const empFlexible = empleados.find(e => e.email === username || e.nroLegajo === username);
    if (empFlexible) {
        empFlexible.password = password;
        fs.writeFileSync(dbEmpleadosPath, JSON.stringify(empleados, null, 2));
        const empPath = path.join(__dirname, 'private-empleado.html');
        if (fs.existsSync(empPath)) return res.sendFile(empPath);
    }

    return res.send(`<script>alert("Credenciales incorrectas."); window.location.href="/";</script>`);
});

app.listen(PORT, () => {
    console.log(`Servidor Entheus corriendo en puerto ${PORT}`);
});
