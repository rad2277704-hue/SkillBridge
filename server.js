require('dotenv').config({ path: require('path').join(__dirname, '.env') });

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const CryptoJS = require('crypto-js');

const db = require('./db');
const dbOp = require('./db-operativo');
const motor = require('./motor-heuristico');
const { evaluarConIA } = require('./ia-motor');
const { enviarCodigoVerificacion, enviarClaveEmpresa, enviarCodigoRestablecimiento, enviarCorreoSoporte } = require('./emailService');
const { cifrarAES, descifrarAES } = require('./crypto-empresa');
const { dominios_permitidos: DOMINIOS_PERMITIDOS } = require('./dominios_universidades.json');

const app = express();

let verificarIntegridad = null;
try { verificarIntegridad = require('./seguridad/integridad').verificarIntegridad; } catch (_e) {}
(function () {
  if (!verificarIntegridad) return;
  const r = verificarIntegridad();
  if (!r.ok) {
    console.error('╔══════════════════════════╗');
    console.error('║  ⚠  SKILLBRIDGE — INTEGRIDAD COMPROMETIDA                ║');
    console.error('╠══════════════════════════╣');
    console.error('║  Se detectaron cambios NO autorizados en la aplicación.  ║');
    console.error('║  ' + (r.motivo || '').padEnd(55) + '║');
    console.error('║  ' + ((r.detalle || '').slice(0, 55)).padEnd(55) + '║');
    console.error('║                                                          ║');
    console.error('║  La app queda BLOQUEADA. Solo el creador puede restable- ║');
    console.error('║  cerla re-sellando con su clave maestra:                 ║');
    console.error('║    node seguridad/herramientas-propietario.js sellar     ║');
    console.error('╚══════════════════════════╝');
    process.exit(1);
  }
  if (r.sin_sellar) {
    console.warn('[integridad] La app aún no está sellada (sin manifiesto). Ejecuta: node seguridad/herramientas-propietario.js sellar');
  } else if (r.aviso) {
    console.warn('[integridad] ' + r.aviso);
  } else {
    console.log('[integridad] ✔ Código verificado — la app coincide con el sello del creador.');
  }
})();

const PUERTO = process.env.PORT || 3000;
const API_REMOTA_HABILITADA = process.env.REMOTE_API_ENABLED === 'true';

const VENCIMIENTO_CODIGO_MS = 24 * 60 * 60 * 1000; // 1 día, según lo definido
const MAX_INTENTOS_CODIGO = 5;
const VENCIMIENTO_CODIGO_RESET_MS = 30 * 60 * 1000; // 30 minutos — más corto que el de verificación por seguridad
const COOLDOWN_REENVIO_MS = 60 * 1000; // 1 minuto entre reenvíos
const RONDAS_BCRYPT = 12;

const COOKIE_SESION = 'sb_sesion';
const SESION_DURACION = '7d';
const SESION_DURACION_MS = 7 * 24 * 60 * 60 * 1000;

const COOKIE_SESION_EMPRESA = 'sb_sesion_empresa';

const CLAVE_TRANSPORTE_DEMO = 'skillbridge-transporte-empresarial-demo';
const CORREOS_CREADOR = new Set(['robertoduran@panamaschool.edu.pa']);

const PLANES_VALIDOS = ['platinum', 'gold'];
const MODALIDADES_PAGO_VALIDAS = ['pago_hoy', 'mes_prueba'];

const JWT_SECRET = process.env.JWT_SECRET || (() => {
  console.warn(
    '[server] JWT_SECRET no está definido en .env — se generó una clave temporal ' +
    'solo para esta ejecución. Cada vez que reinicies el servidor, las sesiones ' +
    'activas se invalidarán. Define JWT_SECRET en .env antes de producción.'
  );
  return crypto.randomBytes(32).toString('hex');
})();

app.use(express.json({ limit: '2mb' })); // soporte adjunta archivos en base64 y soluciones envían código
app.use(cookieParser());

const ORIGENES_PERMITIDOS = new Set(
  String(process.env.FRONTEND_ORIGIN || 'tauri://localhost,https://tauri.localhost,http://tauri.localhost')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
);
const ES_ORIGEN_LOCAL = (origin) =>
  /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(String(origin || ''));
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || ORIGENES_PERMITIDOS.has(origin) || ES_ORIGEN_LOCAL(origin)) return cb(null, true);
      return cb(null, false); // sin cabecera CORS: el navegador bloquea la respuesta
    },
    credentials: true,
  })
);

app.use((req, res, next) => {
  if (API_REMOTA_HABILITADA) return next();
  const ip = req.socket.remoteAddress || '';
  const esLocal = ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
  if (!esLocal) return res.status(403).json({ error: 'Acceso permitido solo desde este equipo.' });
  next();
});

const limitadorSensible = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiados intentos. Intenta de nuevo en unos minutos.' },
});
app.use('/api/registro', limitadorSensible);
app.use('/api/verificar', limitadorSensible);
app.use('/api/reenviar-codigo', limitadorSensible);
app.use('/api/login', limitadorSensible);
app.use('/api/solicitar-restablecimiento', limitadorSensible);
app.use('/api/restablecer-contrasena', limitadorSensible);
app.use('/api/empresas/registro', limitadorSensible);
app.use('/api/empresas/login', limitadorSensible);
app.use('/api/soporte', limitadorSensible);

const REGEX_CORREO = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function extraerDominio(correo) {
  return correo.toLowerCase().split('@')[1] || '';
}

function compilarPatronesDominio(patrones) {
  return patrones.map((patron) => {
    const partes = patron.split('*').map((parte) =>
      parte.replace(/[.+?^${}()|[\]\\]/g, '\\$&') // escapar todo lo que sea regex especial
    );
    return new RegExp(partes.join('[^.]+') + '$', 'i'); // el dominio debe TERMINAR en el patrón
  });
}

const PATRONES_DOMINIO = compilarPatronesDominio(DOMINIOS_PERMITIDOS);

function esCorreoCreador(correo) {
  return CORREOS_CREADOR.has(String(correo || '').trim().toLowerCase());
}

function leerListaPerfil(valor, predeterminado) {
  try {
    const lista = JSON.parse(valor || 'null');
    return Array.isArray(lista) && lista.length ? lista : predeterminado;
  } catch (_error) {
    return predeterminado;
  }
}

function esDominioInstitucional(correo) {
  const dominio = extraerDominio(correo);
  return esCorreoCreador(correo) || PATRONES_DOMINIO.some((regex) => regex.test(dominio));
}

function generarCodigo() {
  return crypto.randomInt(0, 1_000_000).toString().padStart(6, '0');
}

function generarClaveEmpresa() {
  const alfabeto = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  let sufijo = '';
  for (let i = 0; i < 10; i++) {
    sufijo += alfabeto[crypto.randomInt(0, alfabeto.length)];
  }
  return `SB-EMP-${sufijo}`;
}

function descifrarTransporte(valorCifrado, nombreCampo) {
  try {
    const bytes = CryptoJS.AES.decrypt(String(valorCifrado), CLAVE_TRANSPORTE_DEMO);
    const texto = bytes.toString(CryptoJS.enc.Utf8);
    if (!texto) throw new Error('vacío');
    return texto;
  } catch (_error) {
    throw new Error(`No se pudo procesar el campo "${nombreCampo}". Vuelve a intentar el registro.`);
  }
}

async function crearYEnviarCodigo(usuario, { esReenvio = false } = {}) {
  const codigo = generarCodigo();
  const codigo_hash = await bcrypt.hash(codigo, RONDAS_BCRYPT);

  db.guardarNuevoCodigo({
    id: usuario.id,
    codigo_hash,
    codigo_expira_en: Date.now() + VENCIMIENTO_CODIGO_MS,
    codigo_enviado_en: Date.now(),
  });

  try {
    await enviarCodigoVerificacion({
      nombre: usuario.nombre,
      correo: usuario.correo,
      codigo,
    });
    return { correoEnviado: true };
  } catch (errorCorreo) {
    console.error(
      `[server] No se pudo enviar el código a ${usuario.correo}:`,
      errorCorreo.message
    );
    return { correoEnviado: false };
  }
}

app.post('/api/registro', async (req, res) => {
  try {
    const { nombre, correo, contrasena, carrera } = req.body || {};

    if (!nombre || !correo || !contrasena) {
      return res.status(400).json({ error: 'Nombre, correo y contraseña son obligatorios.' });
    }
    if (nombre.trim().length < 2 || nombre.length > 120) {
      return res.status(400).json({ error: 'El nombre no es válido.' });
    }
    if (!REGEX_CORREO.test(correo)) {
      return res.status(400).json({ error: 'El correo no tiene un formato válido.' });
    }
    if (contrasena.length < 8) {
      return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres.' });
    }
    if (!esDominioInstitucional(correo)) {
      return res.status(400).json({
        error: 'Ese correo no pertenece a una institución educativa registrada en SkillBridge.',
      });
    }

    const correoNormalizado = correo.toLowerCase();
    const existente = db.buscarPorCorreo(correoNormalizado);

    if (existente && existente.verificado) {
      return res.status(409).json({
        error: 'Ya existe una cuenta con ese correo. Intenta iniciar sesión o verificarla.',
      });
    }

    let usuario;
    let codigo;
    let correoEnviado = true;

    if (existente && !existente.verificado) {
      const nuevaContrasenaHash = await bcrypt.hash(contrasena, RONDAS_BCRYPT);
      codigo = generarCodigo();
      const codigo_hash = await bcrypt.hash(codigo, RONDAS_BCRYPT);

      db.actualizarContrasena(existente.id, nuevaContrasenaHash);
      db.guardarNuevoCodigo({
        id: existente.id,
        codigo_hash,
        codigo_expira_en: Date.now() + VENCIMIENTO_CODIGO_MS,
        codigo_enviado_en: Date.now(),
      });

      usuario = { ...existente, nombre: nombre.trim(), dominio: extraerDominio(correoNormalizado), carrera: carrera ? String(carrera).trim() : null };

      try {
        await enviarCodigoVerificacion({ nombre: usuario.nombre, correo: usuario.correo, codigo });
      } catch (errorCorreo) {
        correoEnviado = false;
        console.error(
          `[server] La cuenta de ${usuario.correo} ya existía sin verificar, pero el correo con el nuevo código NO se pudo enviar:`,
          errorCorreo.message
        );
      }

      return res.status(200).json({
        mensaje: correoEnviado
          ? 'Ya tenías una cuenta sin verificar. Te enviamos un nuevo código para terminar tu registro.'
          : 'Ya tenías una cuenta sin verificar, pero no pudimos enviar el nuevo código ahora mismo. Intenta reenviarlo más tarde.',
        correo: usuario.correo,
        correoEnviado,
        reenvio: true,
      });
    }

    const contrasena_hash = await bcrypt.hash(contrasena, RONDAS_BCRYPT);
    codigo = generarCodigo();
    const codigo_hash = await bcrypt.hash(codigo, RONDAS_BCRYPT);

    usuario = db.crearUsuario({
      nombre: nombre.trim(),
      correo: correoNormalizado,
      dominio: extraerDominio(correoNormalizado),
      contrasena_hash,
      carrera: carrera ? String(carrera).trim() : null,
      codigo_hash,
      codigo_expira_en: Date.now() + VENCIMIENTO_CODIGO_MS,
      codigo_enviado_en: Date.now(),
      creado_en: Date.now(),
    });

    try {
      await enviarCodigoVerificacion({ nombre: usuario.nombre, correo: usuario.correo, codigo });
    } catch (errorCorreo) {
      correoEnviado = false;
      console.error(
        `[server] La cuenta de ${usuario.correo} se creó, pero el correo con el código NO se pudo enviar:`,
        errorCorreo.message
      );
    }

    return res.status(201).json({
      mensaje: correoEnviado
        ? 'Cuenta creada. Revisa tu correo institucional para el código de verificación.'
        : 'Cuenta creada, pero no pudimos enviar el correo con el código ahora mismo. Usa "Reenviar código" en un momento.',
      correo: usuario.correo,
      correoEnviado,
    });
  } catch (error) {
    console.error('Error en /api/registro:', error);
    return res.status(500).json({ error: 'Ocurrió un error inesperado. Intenta de nuevo.' });
  }
});

app.post('/api/verificar', async (req, res) => {
  try {
    const { correo, codigo } = req.body || {};
    if (!correo || !codigo) {
      return res.status(400).json({ error: 'Correo y código son obligatorios.' });
    }

    const usuario = db.buscarPorCorreo(correo);
    if (!usuario) {
      return res.status(404).json({ error: 'No encontramos una cuenta con ese correo.' });
    }
    if (usuario.verificado) {
      return res.status(200).json({ mensaje: 'Este correo ya estaba verificado.' });
    }
    if (!usuario.codigo_hash || !usuario.codigo_expira_en) {
      return res.status(400).json({ error: 'No hay un código activo. Solicita uno nuevo.' });
    }
    if (Date.now() > usuario.codigo_expira_en) {
      return res.status(400).json({ error: 'El código venció. Solicita uno nuevo.' });
    }
    if (usuario.codigo_intentos >= MAX_INTENTOS_CODIGO) {
      return res.status(429).json({ error: 'Demasiados intentos fallidos. Solicita un código nuevo.' });
    }

    const coincide = await bcrypt.compare(String(codigo), usuario.codigo_hash);
    if (!coincide) {
      db.incrementarIntentos(usuario.id);
      const intentosRestantes = MAX_INTENTOS_CODIGO - (usuario.codigo_intentos + 1);
      return res.status(400).json({
        error: 'Código incorrecto.',
        intentosRestantes: Math.max(intentosRestantes, 0),
      });
    }

    db.marcarVerificado(usuario.id);
    return res.status(200).json({ mensaje: 'Correo institucional verificado correctamente.' });
  } catch (error) {
    console.error('Error en /api/verificar:', error);
    return res.status(500).json({ error: 'Ocurrió un error inesperado. Intenta de nuevo.' });
  }
});

app.post('/api/reenviar-codigo', async (req, res) => {
  try {
    const { correo } = req.body || {};
    if (!correo) {
      return res.status(400).json({ error: 'El correo es obligatorio.' });
    }

    const usuario = db.buscarPorCorreo(correo);
    if (!usuario) {
      return res.status(404).json({ error: 'No encontramos una cuenta con ese correo.' });
    }
    if (usuario.verificado) {
      return res.status(200).json({ mensaje: 'Este correo ya estaba verificado.' });
    }
    if (
      usuario.codigo_enviado_en &&
      Date.now() - usuario.codigo_enviado_en < COOLDOWN_REENVIO_MS
    ) {
      const segundosRestantes = Math.ceil(
        (COOLDOWN_REENVIO_MS - (Date.now() - usuario.codigo_enviado_en)) / 1000
      );
      return res.status(429).json({
        error: `Espera ${segundosRestantes} segundos antes de pedir otro código.`,
      });
    }

    const { correoEnviado } = await crearYEnviarCodigo(usuario, { esReenvio: true });
    return res.status(200).json({
      mensaje: correoEnviado
        ? 'Enviamos un nuevo código a tu correo.'
        : 'Generamos un nuevo código, pero no pudimos enviarlo por correo ahora mismo. Intenta de nuevo en un momento.',
      correoEnviado,
    });
  } catch (error) {
    console.error('Error en /api/reenviar-codigo:', error);
    return res.status(500).json({ error: 'Ocurrió un error inesperado. Intenta de nuevo.' });
  }
});

app.post('/api/soporte', async (req, res) => {
  try {
    const { nombre, correo, asunto, mensaje, archivos } = req.body || {};
    if (!nombre || !correo || !asunto || !mensaje) {
      return res.status(400).json({ error: 'Nombre, correo, asunto y mensaje son obligatorios.' });
    }
    if (!REGEX_CORREO.test(correo)) {
      return res.status(400).json({ error: 'El correo no tiene un formato válido.' });
    }
    if (String(mensaje).length > 4000) {
      return res.status(400).json({ error: 'El mensaje es demasiado largo (máximo 4,000 caracteres).' });
    }

    let archivosValidos = [];
    if (Array.isArray(archivos) && archivos.length) {
      if (archivos.length > 5) {
        return res.status(400).json({ error: 'Máximo 5 archivos por mensaje.' });
      }
      for (const a of archivos) {
        if (!a || !a.nombre || typeof a.contenidoBase64 !== 'string') {
          return res.status(400).json({ error: 'Archivo adjunto inválido.' });
        }
        if (a.contenidoBase64.length > 400_000) {
          return res.status(400).json({ error: `El archivo "${a.nombre}" supera el tamaño máximo (300 KB).` });
        }
        archivosValidos.push({
          nombre: String(a.nombre).slice(0, 200),
          tamano: Math.floor((a.contenidoBase64.length * 3) / 4),
          contenidoBase64: a.contenidoBase64,
        });
      }
    }

    const resultado = await enviarCorreoSoporte({
      nombre: String(nombre).slice(0, 120),
      correo: String(correo).toLowerCase(),
      asunto: String(asunto).slice(0, 200),
      mensaje: String(mensaje),
      archivos: archivosValidos,
    });

    if (resultado.enviado === false) {
      return res.status(503).json({
        error: 'El servicio de correo no está disponible ahora mismo. Intenta más tarde o escríbenos directamente.',
      });
    }

    return res.status(200).json({ mensaje: 'Mensaje enviado. El equipo de soporte te responderá a tu correo.' });
  } catch (error) {
    console.error('Error en POST /api/soporte:', error);
    return res.status(500).json({ error: 'No se pudo enviar el mensaje. Intenta de nuevo.' });
  }
});

app.get('/api/salud', (_req, res) => res.json({ estado: 'ok' }));

app.post('/api/solicitar-restablecimiento', async (req, res) => {
  const { correo } = req.body || {};
  const mensajeGenerico = { mensaje: 'Si ese correo tiene una cuenta, te enviamos un código para restablecer tu contraseña.' };

  if (!correo) {
    return res.status(400).json({ error: 'El correo es obligatorio.' });
  }

  try {
    const usuario = db.buscarPorCorreo(correo);
    if (!usuario || !usuario.verificado) {
      return res.status(200).json(mensajeGenerico);
    }

    const codigo = generarCodigo();
    const codigo_hash = await bcrypt.hash(codigo, RONDAS_BCRYPT);

    db.guardarCodigoReset({
      id: usuario.id,
      reset_codigo_hash: codigo_hash,
      reset_codigo_expira_en: Date.now() + VENCIMIENTO_CODIGO_RESET_MS,
      reset_codigo_enviado_en: Date.now(),
    });

    await enviarCodigoRestablecimiento({ nombre: usuario.nombre, correo: usuario.correo, codigo });

    return res.status(200).json(mensajeGenerico);
  } catch (error) {
    console.error('Error en /api/solicitar-restablecimiento:', error);
    return res.status(200).json(mensajeGenerico);
  }
});

app.post('/api/restablecer-contrasena', async (req, res) => {
  try {
    const { correo, codigo, nuevaContrasena, repetirContrasena } = req.body || {};
    if (!correo || !codigo || !nuevaContrasena || !repetirContrasena) {
      return res.status(400).json({ error: 'Correo, código y ambas contraseñas son obligatorios.' });
    }
    if (nuevaContrasena.length < 8) {
      return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 8 caracteres.' });
    }
    if (nuevaContrasena !== repetirContrasena) {
      return res.status(400).json({ error: 'Las contraseñas no coinciden.' });
    }

    const usuario = db.buscarPorCorreo(correo);
    if (!usuario) {
      return res.status(400).json({ error: 'Código incorrecto o vencido.' });
    }
    if (!usuario.reset_codigo_hash || !usuario.reset_codigo_expira_en) {
      return res.status(400).json({ error: 'No hay una solicitud de restablecimiento activa. Pide un código nuevo.' });
    }
    if (Date.now() > usuario.reset_codigo_expira_en) {
      return res.status(400).json({ error: 'El código venció. Solicita uno nuevo.' });
    }
    if (usuario.reset_codigo_intentos >= MAX_INTENTOS_CODIGO) {
      return res.status(429).json({ error: 'Demasiados intentos fallidos. Solicita un código nuevo.' });
    }

    const coincide = await bcrypt.compare(String(codigo), usuario.reset_codigo_hash);
    if (!coincide) {
      db.incrementarIntentosReset(usuario.id);
      return res.status(400).json({ error: 'Código incorrecto.' });
    }

    const contrasena_hash = await bcrypt.hash(nuevaContrasena, RONDAS_BCRYPT);
    db.actualizarContrasena(usuario.id, contrasena_hash);

    return res.status(200).json({ mensaje: 'Tu contraseña quedó actualizada. Ya puedes iniciar sesión.' });
  } catch (error) {
    console.error('Error en /api/restablecer-contrasena:', error);
    return res.status(500).json({ error: 'Ocurrió un error inesperado. Intenta de nuevo.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { correo, contrasena } = req.body || {};
    if (!correo || !contrasena) {
      return res.status(400).json({ error: 'Correo y contraseña son obligatorios.' });
    }

    const credencialesInvalidas = () =>
      res.status(401).json({ error: 'Correo o contraseña incorrectos.' });

    const usuario = db.buscarPorCorreo(correo);
    if (!usuario) return credencialesInvalidas();

    const coincide = await bcrypt.compare(contrasena, usuario.contrasena_hash);
    if (!coincide) return credencialesInvalidas();

    if (!usuario.verificado) {
      return res.status(403).json({
        error: 'Todavía no has verificado tu correo institucional.',
        correoNoVerificado: true,
      });
    }

    const token = jwt.sign({ sub: usuario.id, correo: usuario.correo }, JWT_SECRET, {
      expiresIn: SESION_DURACION,
    });

    res.cookie(COOKIE_SESION, token, {
      httpOnly: true, // JavaScript del navegador no puede leer esta cookie
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production', // exige HTTPS en producción
      maxAge: SESION_DURACION_MS,
    });

    return res.status(200).json({
      mensaje: 'Sesión iniciada correctamente.',
      nombre: usuario.nombre,
      correo: usuario.correo,
      token,
    });
  } catch (error) {
    console.error('Error en /api/login:', error);
    return res.status(500).json({ error: 'Ocurrió un error inesperado. Intenta de nuevo.' });
  }
});

app.get('/api/sesion', (req, res) => {
  const token = obtenerToken(req, COOKIE_SESION);
  if (!token) return res.status(401).json({ error: 'No hay sesión activa.' });

  try {
    const datos = jwt.verify(token, JWT_SECRET);
    const usuario = db.buscarPorId(datos.sub);
    if (!usuario) return res.status(401).json({ error: 'No hay sesión activa.' });

    return res.json({
      id: usuario.id,
      nombre: usuario.nombre,
      correo: usuario.correo,
      carrera: usuario.carrera,
      verificado: !!usuario.verificado,
    });
  } catch (_error) {
    return res.status(401).json({ error: 'Tu sesión venció o no es válida. Inicia sesión de nuevo.' });
  }
});

app.get('/api/feed', requireEstudiante, (req, res) => {
  try {
    const usuario = db.buscarPorId(req.usuarioId);
    if (!usuario) return res.status(401).json({ error: 'No hay sesión activa.' });

    const empresas = db.listarEmpresas().map((empresa) => ({
      id: empresa.id,
      nombre: empresa.nombre_empresa,
      sector: empresa.sector || (empresa.plan === 'gold' ? 'Tecnología' : 'Consultoría'),
      descripcion: empresa.descripcion || '',
      plan: empresa.plan,
    }));

    const retos = dbOp.listarRetos().map((reto) => {
      const empresa = db.buscarEmpresaPorId(reto.empresa_id);
      return {
        id: reto.id,
        empresaId: reto.empresa_id,
        empresa: empresa ? empresa.nombre_empresa : 'Empresa',
        titulo: reto.titulo,
        sector: reto.sector,
        dificultad: reto.dificultad,
        descripcion: reto.descripcion,
        plazo: `${reto.plazo_horas}h`,
        fechaLimite: reto.fecha_limite,
        publicadoEn: reto.publicado_en,
      };
    });

    const seguidas = dbOp.listarSeguidasPorUsuario(req.usuarioId).map((empresa) => String(empresa.id));

    return res.json({
      estudiante: {
        id: usuario.id,
        nombre: usuario.nombre,
        correo: usuario.correo,
        carrera: usuario.carrera || '',
        especialidades: leerListaPerfil(usuario.especialidades, []),
        habilidades: leerListaPerfil(usuario.habilidades, []),
        frase: usuario.frase || '',
        puntajeMaximo: esCorreoCreador(usuario.correo) ? 1000 : 0,
      },
      empresas,
      retos,
      seguidas,
      notificaciones: dbOp.listarAlertasDeUsuario(req.usuarioId),
    });
  } catch (error) {
    console.error('Error en GET /api/feed:', error);
    return res.status(500).json({ error: 'No se pudo cargar el feed.' });
  }
});

app.get('/api/perfil', requireEstudiante, (req, res) => {
  try {
    const usuario = db.buscarPorId(req.usuarioId);
    if (!usuario) return res.status(401).json({ error: 'No hay sesión activa.' });

    const soluciones = dbOp.listarSolucionesDeUsuario(req.usuarioId);
    const seguidas = dbOp.listarSeguidasPorUsuario(req.usuarioId);
    const puntajeMaximo = soluciones.reduce((max, s) => Math.max(max, Number(s.puntuacion || 0)), 0);

    return res.json({
      estudiante: {
        id: usuario.id,
        nombre: usuario.nombre,
        correo: usuario.correo,
        carrera: usuario.carrera || '',
        edad: usuario.edad || null,
        institucion: usuario.institucion || '',
        especialidades: leerListaPerfil(usuario.especialidades, []),
        habilidades: leerListaPerfil(usuario.habilidades, []),
        frase: usuario.frase || '',
        puntajeMaximo: esCorreoCreador(usuario.correo) ? 1000 : puntajeMaximo,
        participaciones: soluciones.length,
        contratos: 0,
        solucionesPropuestas: soluciones.length,
      },
      seguidas: seguidas.length,
      soluciones,
      insignias: [],
    });
  } catch (error) {
    console.error('Error en GET /api/perfil:', error);
    return res.status(500).json({ error: 'No se pudo cargar el perfil.' });
  }
});

function deserializarAnalisis(solucion) {
  const informe = String(solucion.informe || '');
  const m = informe.match(/DETECCIÓN DE IA:\s*(\d+)%/i);
  const m2 = informe.match(/SEÑAL LEVE DE IA:\s*(\d+)%/i);
  const probabilidadIA = m ? Number(m[1]) : m2 ? Number(m2[1]) : 0;
  const nivel = probabilidadIA >= 80 ? 'confirmado'
    : probabilidadIA >= 55 ? 'muy_probable'
    : probabilidadIA > 0 ? 'sospechoso' : 'humano';
  return { probabilidadIA, nivel, motivos: [] };
}

app.post('/api/perfil', requireEstudiante, (req, res) => {
  try {
    const usuario = db.buscarPorId(req.usuarioId);
    if (!usuario) return res.status(401).json({ error: 'No hay sesión activa.' });

    const { nombre, edad, institucion, especialidades, habilidades, frase } = req.body || {};
    if (!nombre || nombre.trim().length < 2 || nombre.trim().length > 120) {
      return res.status(400).json({ error: 'El nombre no es válido.' });
    }
    if (!Number.isInteger(Number(edad)) || Number(edad) < 15 || Number(edad) > 99) {
      return res.status(400).json({ error: 'La edad debe estar entre 15 y 99 años.' });
    }
    const limpiarLista = (lista) => Array.isArray(lista)
      ? lista.map((item) => String(item).trim()).filter(Boolean).slice(0, 20)
      : [];
    const actualizado = db.actualizarPerfil({
      id: req.usuarioId,
      nombre: nombre.trim(),
      edad: Number(edad),
      institucion: String(institucion || '').trim().slice(0, 160),
      especialidades: JSON.stringify(limpiarLista(especialidades)),
      habilidades: JSON.stringify(limpiarLista(habilidades)),
      frase: String(frase || '').trim().slice(0, 160),
    });
    return res.json({ estudiante: {
      id: actualizado.id,
      nombre: actualizado.nombre,
      correo: actualizado.correo,
      carrera: actualizado.carrera,
      edad: actualizado.edad,
      institucion: actualizado.institucion,
      especialidades: leerListaPerfil(actualizado.especialidades, []),
      habilidades: leerListaPerfil(actualizado.habilidades, []),
      frase: actualizado.frase || '',
      puntajeMaximo: esCorreoCreador(actualizado.correo) ? 1000 : 0,
    } });
  } catch (error) {
    console.error('Error en POST /api/perfil:', error);
    return res.status(500).json({ error: 'No se pudo guardar tu perfil.' });
  }
});

app.get('/api/empresas', requireEstudiante, (req, res) => {
  try {
    const empresas = db.listarEmpresas().map((empresa) => ({
      id: empresa.id,
      nombre: empresa.nombre_empresa,
      sector: empresa.sector || (empresa.plan === 'gold' ? 'Tecnología' : 'Consultoría'),
      descripcion: empresa.descripcion || '',
      plan: empresa.plan,
    }));
    return res.json({ empresas });
  } catch (error) {
    console.error('Error en GET /api/empresas:', error);
    return res.status(500).json({ error: 'No se pudieron cargar las empresas.' });
  }
});

app.get('/api/empresas/:id(\\d+)/perfil', requireEstudiante, (req, res) => {
  try {
    const empresa = db.buscarEmpresaPorId(req.params.id);
    if (!empresa) return res.status(404).json({ error: 'No encontramos esa empresa.' });

    dbOp.cerrarRetosVencidos();
    const retos = dbOp.listarRetosDeEmpresaConConteo(empresa.id) || [];
    const abiertos = retos.filter((r) => r.estado === 'abierto');

    const seguidas = dbOp.listarSeguidasPorUsuario(req.usuarioId).map((e) => String(e.id));

    return res.json({
      empresa: {
        id: empresa.id,
        nombre: empresa.nombre_empresa,
        sector: empresa.sector || (empresa.plan === 'gold' ? 'Tecnología' : 'Consultoría'),
        descripcion: empresa.descripcion || 'Esta empresa todavía no escribió su descripción.',
        plan: empresa.plan,
        creadoEn: empresa.creado_en,
      },
      estadisticas: {
        retosAbiertos: abiertos.length,
        retosTotales: retos.length,
        seguidores: dbOp.contarSeguidores(empresa.id),
      },
      retos: abiertos.map((r) => ({
        id: r.id,
        titulo: r.titulo,
        descripcion: r.descripcion,
        dificultad: r.dificultad,
        plazo: `${r.plazo_horas}h`,
        soluciones: r.total_soluciones || 0,
      })),
      sigues: seguidas.includes(String(empresa.id)),
    });
  } catch (error) {
    console.error('Error en GET /api/empresas/:id/perfil:', error);
    return res.status(500).json({ error: 'No se pudo cargar el perfil de la empresa.' });
  }
});

app.get('/api/empresas/perfil', requireEmpresa, (req, res) => {
  try {
    const empresa = db.buscarEmpresaPorId(req.empresaId);
    if (!empresa) return res.status(404).json({ error: 'No encontramos tu cuenta empresarial.' });
    return res.json({
      empresa: {
        id: empresa.id,
        nombre: empresa.nombre_empresa,
        sector: empresa.sector || '',
        descripcion: empresa.descripcion || '',
        plan: empresa.plan,
      },
    });
  } catch (error) {
    console.error('Error en GET /api/empresas/perfil:', error);
    return res.status(500).json({ error: 'No se pudo cargar tu perfil.' });
  }
});

app.post('/api/empresas/perfil', requireEmpresa, (req, res) => {
  try {
    const { descripcion, sector } = req.body || {};
    const texto = String(descripcion || '').trim();
    if (texto.length > 600) {
      return res.status(400).json({ error: 'La descripción no puede superar los 600 caracteres.' });
    }
    const empresa = db.actualizarPerfilEmpresa({
      id: req.empresaId,
      descripcion: texto || null,
      sector: String(sector || '').trim() || null,
    });
    return res.json({
      mensaje: 'Perfil actualizado.',
      empresa: { id: empresa.id, descripcion: empresa.descripcion, sector: empresa.sector },
    });
  } catch (error) {
    console.error('Error en POST /api/empresas/perfil:', error);
    return res.status(500).json({ error: 'No se pudo guardar tu perfil.' });
  }
});

app.get('/api/soluciones/:id/estudiante', requireEmpresa, (req, res) => {
  try {
    const solucion = dbOp.obtenerSolucion(Number(req.params.id));
    if (!solucion) return res.status(404).json({ error: 'No encontramos esa solución.' });

    const reto = dbOp.obtenerReto(solucion.reto_id);
    if (!reto || reto.empresa_id !== req.empresaId) {
      return res.status(403).json({ error: 'Solo puedes ver el perfil de estudiantes que enviaron soluciones a TUS retos.' });
    }

    const estudiante = db.buscarPorId(solucion.usuario_id);
    if (!estudiante) return res.status(404).json({ error: 'No encontramos al estudiante.' });

    const listar = (campo) => {
      try { return JSON.parse(estudiante[campo] || '[]'); } catch (_e) { return []; }
    };

    return res.json({
      estudiante: {
        id: estudiante.id,
        nombre: estudiante.nombre,
        correo: estudiante.correo,
        carrera: estudiante.carrera || '',
        institucion: estudiante.institucion || '',
        edad: estudiante.edad || null,
        frase: estudiante.frase || '',
        especialidades: listar('especialidades'),
        habilidades: listar('habilidades'),
      },
      solucion: {
        id: solucion.id,
        puntuacion: solucion.puntuacion,
        rango: solucion.rango_letra,
        estado: solucion.estado,
      },
      reto: { id: reto.id, titulo: reto.titulo },
    });
  } catch (error) {
    console.error('Error en GET /api/soluciones/:id/estudiante:', error);
    return res.status(500).json({ error: 'No se pudo cargar el perfil del estudiante.' });
  }
});

app.post('/api/logout', (_req, res) => {
  res.clearCookie(COOKIE_SESION);
  return res.json({ mensaje: 'Sesión cerrada.' });
});

app.post('/api/empresas/registro', async (req, res) => {
  try {
    const {
      nombreEmpresa,
      rucNitCifrado,
      telefonoCifrado,
      correoCorporativo,
      nombreContacto,
      contrasena,
      plan,
      modalidadPago,
    } = req.body || {};

    if (!nombreEmpresa || !rucNitCifrado || !telefonoCifrado || !correoCorporativo || !nombreContacto || !contrasena) {
      return res.status(400).json({ error: 'Completa todos los campos de la empresa.' });
    }
    if (!REGEX_CORREO.test(correoCorporativo)) {
      return res.status(400).json({ error: 'El correo corporativo no tiene un formato válido.' });
    }
    if (contrasena.length < 8) {
      return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres.' });
    }
    if (!PLANES_VALIDOS.includes(plan)) {
      return res.status(400).json({ error: 'El plan seleccionado no es válido.' });
    }
    if (!MODALIDADES_PAGO_VALIDAS.includes(modalidadPago)) {
      return res.status(400).json({ error: 'La modalidad de pago no es válida.' });
    }

    const correoNormalizado = correoCorporativo.toLowerCase();
    const existente = db.buscarEmpresaPorCorreo(correoNormalizado);
    if (existente) {
      return res.status(409).json({
        error: 'Ya existe una cuenta empresarial con ese correo.',
      });
    }

    const rucNit = descifrarTransporte(rucNitCifrado, 'RUC/NIT');
    const telefono = descifrarTransporte(telefonoCifrado, 'teléfono de contacto');

    const contrasena_hash = await bcrypt.hash(contrasena, RONDAS_BCRYPT);

    const clave = generarClaveEmpresa();
    const clave_empresa_hash = await bcrypt.hash(clave, RONDAS_BCRYPT);

    const estado_pago = modalidadPago === 'mes_prueba' ? 'prueba_activa' : 'pago_pendiente_confirmacion';

    const empresa = db.crearEmpresa({
      nombre_empresa: nombreEmpresa.trim(),
      ruc_nit_cifrado: cifrarAES(rucNit),
      telefono_cifrado: cifrarAES(telefono),
      correo_corporativo: correoNormalizado,
      nombre_contacto: nombreContacto.trim(),
      contrasena_hash,
      plan,
      modalidad_pago: modalidadPago,
      estado_pago,
      clave_empresa_hash,
      creado_en: Date.now(),
    });

    await enviarClaveEmpresa({
      nombreContacto: empresa.nombre_contacto,
      nombreEmpresa: empresa.nombre_empresa,
      correo: empresa.correo_corporativo,
      clave,
      plan: empresa.plan,
      modalidadPago: empresa.modalidad_pago,
    });

    return res.status(201).json({
      mensaje: 'Cuenta empresarial creada. Revisa tu correo corporativo para tu clave de empresa.',
      correo: empresa.correo_corporativo,
      plan: empresa.plan,
      modalidadPago: empresa.modalidad_pago,
    });
  } catch (error) {
    console.error('Error en /api/empresas/registro:', error);
    if (error.message && error.message.startsWith('No se pudo procesar el campo')) {
      return res.status(400).json({ error: error.message });
    }
    return res.status(500).json({ error: 'Ocurrió un error inesperado. Intenta de nuevo.' });
  }
});

app.post('/api/empresas/login', async (req, res) => {
  try {
    const { correo, contrasena, claveEmpresa } = req.body || {};
    if (!correo || !contrasena || !claveEmpresa) {
      return res.status(400).json({ error: 'Correo, contraseña y clave de empresa son obligatorios.' });
    }

    const credencialesInvalidas = () =>
      res.status(401).json({ error: 'Correo, contraseña o clave de empresa incorrectos.' });

    const empresa = db.buscarEmpresaPorCorreo(correo);
    if (!empresa) return credencialesInvalidas();

    const contrasenaCoincide = await bcrypt.compare(contrasena, empresa.contrasena_hash);
    if (!contrasenaCoincide) return credencialesInvalidas();

    const claveCoincide = await bcrypt.compare(claveEmpresa, empresa.clave_empresa_hash);
    if (!claveCoincide) return credencialesInvalidas();

    const token = jwt.sign(
      { sub: empresa.id, correo: empresa.correo_corporativo, tipo: 'empresa' },
      JWT_SECRET,
      { expiresIn: SESION_DURACION }
    );

    res.cookie(COOKIE_SESION_EMPRESA, token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: SESION_DURACION_MS,
    });

    return res.status(200).json({
      mensaje: 'Sesión empresarial iniciada correctamente.',
      empresa: {
        id: empresa.id,
        nombreEmpresa: empresa.nombre_empresa,
        correo: empresa.correo_corporativo,
        plan: empresa.plan,
      },
      token,
    });
  } catch (error) {
    console.error('Error en /api/empresas/login:', error);
    return res.status(500).json({ error: 'Ocurrió un error inesperado. Intenta de nuevo.' });
  }
});

app.get('/api/empresas/sesion', (req, res) => {
  const token = obtenerToken(req, COOKIE_SESION_EMPRESA);
  if (!token) return res.status(401).json({ error: 'No hay sesión activa.' });

  try {
    const datos = jwt.verify(token, JWT_SECRET);
    const empresa = db.buscarEmpresaPorId(datos.sub);
    if (!empresa) return res.status(401).json({ error: 'No hay sesión activa.' });

    return res.json({
      nombreEmpresa: empresa.nombre_empresa,
      correo: empresa.correo_corporativo,
      plan: empresa.plan,
      rucNit: descifrarAES(empresa.ruc_nit_cifrado),
      telefono: descifrarAES(empresa.telefono_cifrado),
    });
  } catch (_error) {
    return res.status(401).json({ error: 'Tu sesión venció o no es válida. Inicia sesión de nuevo.' });
  }
});

app.post('/api/empresas/logout', (_req, res) => {
  res.clearCookie(COOKIE_SESION_EMPRESA);
  return res.json({ mensaje: 'Sesión cerrada.' });
});

function obtenerToken(req, nombreCookie) {
  if (req.cookies && req.cookies[nombreCookie]) return req.cookies[nombreCookie];
  const encabezado = req.headers.authorization || '';
  if (encabezado.startsWith('Bearer ')) return encabezado.slice(7);
  return null;
}

function requireEstudiante(req, res, next) {
  const token = obtenerToken(req, COOKIE_SESION);
  if (!token) return res.status(401).json({ error: 'Inicia sesión para continuar.' });
  try {
    const datos = jwt.verify(token, JWT_SECRET);
    req.usuarioId = datos.sub;
    next();
  } catch (_error) {
    return res.status(401).json({ error: 'Tu sesión venció o no es válida.' });
  }
}

function requireEmpresa(req, res, next) {
  const token = obtenerToken(req, COOKIE_SESION_EMPRESA);
  if (!token) return res.status(401).json({ error: 'Inicia sesión como empresa para continuar.' });
  try {
    const datos = jwt.verify(token, JWT_SECRET);
    req.empresaId = datos.sub;
    next();
  } catch (_error) {
    return res.status(401).json({ error: 'Tu sesión de empresa venció o no es válida.' });
  }
}

app.get('/api/empresas/panel', requireEmpresa, (req, res) => {
  try {
    dbOp.cerrarRetosVencidos();
    const empresa = db.buscarEmpresaPorId(req.empresaId);
    if (!empresa) {
      return res.status(404).json({ error: 'No encontramos tu cuenta empresarial.' });
    }

    return res.json({
      empresa: {
        id: empresa.id,
        nombreEmpresa: empresa.nombre_empresa,
        correo: empresa.correo_corporativo,
        nombreContacto: empresa.nombre_contacto,
        plan: empresa.plan,
        modalidadPago: empresa.modalidad_pago,
        estadoPago: empresa.estado_pago,
        creadoEn: empresa.creado_en,
      },
      estadisticas: dbOp.obtenerEstadisticasDeEmpresa(req.empresaId),
      retos: dbOp.listarRetosDeEmpresaConConteo(req.empresaId),
      soluciones: dbOp.listarSolucionesDeEmpresa(req.empresaId).map((s) => ({
        ...s,
        veredictoIA: motor.veredictoIA(deserializarAnalisis(s)),
      })),
    });
  } catch (error) {
    console.error('Error en GET /api/empresas/panel:', error);
    return res.status(500).json({ error: 'No se pudo cargar el panel de empresa.' });
  }
});

app.post('/api/retos', requireEmpresa, (req, res) => {
  try {
    const { titulo, descripcion, requerimientos, metricasEsperadas, sector, dificultad, plazoHoras } = req.body || {};
    if (!titulo || !descripcion || !sector || !dificultad || !plazoHoras) {
      return res.status(400).json({ error: 'Faltan campos obligatorios del reto.' });
    }
    if (![48, 72].includes(Number(plazoHoras))) {
      return res.status(400).json({ error: 'El plazo debe ser 48 o 72 horas.' });
    }
    const ahora = Date.now();
    const reto = dbOp.crearReto({
      empresa_id: req.empresaId,
      titulo,
      descripcion,
      requerimientos: requerimientos ? JSON.stringify(requerimientos) : null,
      metricas_esperadas: metricasEsperadas ? JSON.stringify(metricasEsperadas) : null,
      sector,
      dificultad,
      plazo_horas: Number(plazoHoras),
      publicado_en: ahora,
      fecha_limite: ahora + Number(plazoHoras) * 60 * 60 * 1000,
    });
    return res.status(201).json({ reto });
  } catch (error) {
    console.error('Error en POST /api/retos:', error);
    return res.status(500).json({ error: 'No se pudo crear el reto.' });
  }
});

app.put('/api/retos/:id', requireEmpresa, (req, res) => {
  try {
    const reto = dbOp.obtenerReto(req.params.id);
    if (!reto) return res.status(404).json({ error: 'Ese reto no existe.' });
    if (reto.empresa_id !== req.empresaId) {
      return res.status(403).json({ error: 'Ese reto no pertenece a tu empresa.' });
    }
    const { titulo, descripcion, requerimientos, metricasEsperadas, sector, dificultad } = req.body || {};
    if (!titulo || !descripcion || !sector || !dificultad) {
      return res.status(400).json({ error: 'Faltan campos obligatorios para editar el reto.' });
    }
    const actualizado = dbOp.editarReto(req.params.id, req.empresaId, {
      titulo,
      descripcion,
      requerimientos: requerimientos ? JSON.stringify(requerimientos) : null,
      metricas_esperadas: metricasEsperadas ? JSON.stringify(metricasEsperadas) : null,
      sector,
      dificultad,
    });
    if (!actualizado) return res.status(403).json({ error: 'No se pudo editar ese reto.' });
    return res.json({ reto: actualizado, mensaje: 'Problema actualizado.' });
  } catch (error) {
    console.error('Error en PUT /api/retos/:id:', error);
    return res.status(500).json({ error: 'No se pudo editar el reto.' });
  }
});

app.delete('/api/retos/:id', requireEmpresa, (req, res) => {
  try {
    const reto = dbOp.obtenerReto(req.params.id);
    if (!reto) return res.status(404).json({ error: 'Ese reto no existe.' });
    if (reto.empresa_id !== req.empresaId) {
      return res.status(403).json({ error: 'Ese reto no pertenece a tu empresa.' });
    }
    const ok = dbOp.eliminarReto(req.params.id, req.empresaId);
    if (!ok) return res.status(403).json({ error: 'No se pudo eliminar ese reto.' });
    return res.json({ mensaje: 'Problema eliminado junto con sus soluciones.' });
  } catch (error) {
    console.error('Error en DELETE /api/retos/:id:', error);
    return res.status(500).json({ error: 'No se pudo eliminar el reto.' });
  }
});

app.get('/api/retos', (req, res) => {
  try {
    dbOp.cerrarRetosVencidos();
    const retos = dbOp.listarRetos(req.query.sector);
    return res.json({ retos });
  } catch (error) {
    console.error('Error en GET /api/retos:', error);
    return res.status(500).json({ error: 'No se pudieron cargar los retos.' });
  }
});

app.get('/api/retos/mios', requireEmpresa, (req, res) => {
  try {
    return res.json({ retos: dbOp.listarRetosDeEmpresa(req.empresaId) });
  } catch (error) {
    console.error('Error en GET /api/retos/mios:', error);
    return res.status(500).json({ error: 'No se pudieron cargar tus retos.' });
  }
});

app.get('/api/retos/:id', (req, res) => {
  dbOp.cerrarRetosVencidos();
  const reto = dbOp.obtenerReto(req.params.id);
  if (!reto) return res.status(404).json({ error: 'Ese reto no existe.' });
  const empresaEmisora = dbOp.obtenerEmpresa(reto.empresa_id);
  const nombreEmpresa = empresaEmisora ? empresaEmisora.nombre_empresa : null;
  return res.json({ reto: { ...reto, empresa_nombre: nombreEmpresa } });
});

app.post('/api/soluciones', requireEstudiante, async (req, res) => {
  try {
    const { retoId, codigoOLink, metricas, archivos } = req.body || {};
    if (!retoId || !codigoOLink) {
      return res.status(400).json({ error: 'Falta el reto o el código/link de la solución.' });
    }

    const yaExiste = dbOp.existeSolucionDeEstudiante(retoId, req.usuarioId);
    if (yaExiste) {
      return res.status(409).json({ error: 'Ya has enviado una solución para este reto. Solo se permite una entrega por problema.' });
    }

    dbOp.cerrarRetosVencidos();
    const reto = dbOp.obtenerReto(retoId);
    if (!reto || reto.estado !== 'abierto') {
      return res.status(404).json({ error: 'Ese reto no existe o ya cerró su horario de entrega.' });
    }
    if (Number(reto.fecha_limite) && Date.now() > Number(reto.fecha_limite)) {
      dbOp.cerrarReto(retoId);
      return res.status(404).json({ error: 'Este problema ya cerró: venció el horario de 48/72 horas.' });
    }

    let archivosJSON = null;
    if (Array.isArray(archivos) && archivos.length) {
      if (archivos.length > 10) {
        return res.status(400).json({ error: 'Máximo 10 archivos por solución.' });
      }
      const limpios = [];
      for (const a of archivos) {
        if (!a || !a.nombre || typeof a.contenido !== 'string') {
          return res.status(400).json({ error: 'Archivo adjunto inválido.' });
        }
        if (a.contenido.length > 200_000) {
          return res.status(400).json({ error: `El archivo "${a.nombre}" supera los 200 KB.` });
        }
        limpios.push({ nombre: String(a.nombre).slice(0, 200), tamano: a.contenido.length, contenido: a.contenido });
      }
      archivosJSON = JSON.stringify(limpios);
    }

    const enunciadoReto = `${reto.titulo}. ${reto.descripcion || ''}`;
    let evaluacion = await evaluarConIA({ problema: enunciadoReto, solucion: codigoOLink });
    if (evaluacion) {
      const rangoObj = motor.obtenerRangoPorPuntuacion(evaluacion.puntuacion);
      evaluacion = {
        puntuacion: evaluacion.puntuacion,
        rango: rangoObj.letra,
        mensaje: evaluacion.analisis,
        probabilidadIA: evaluacion.probabilidadIA,
        nivelIA: evaluacion.probabilidadIA >= 80 ? 'confirmado' : evaluacion.probabilidadIA >= 55 ? 'muy_probable' : evaluacion.probabilidadIA >= 28 ? 'sospechoso' : 'humano',
        verificacion: null,
      };
    } else {
      evaluacion = motor.evaluarSolucion({ texto: codigoOLink, codigo: codigoOLink, metricas, enunciadoReto });
    }
    const puntuacion = evaluacion.puntuacion;
    const informe = evaluacion.mensaje;
    const rango = { letra: evaluacion.rango };
    const ahora = Date.now();
    const empresaEmisora = dbOp.obtenerEmpresa(reto.empresa_id);
    const nombreEmpresa = empresaEmisora ? empresaEmisora.nombre_empresa : null;

    const solucion = dbOp.crearSolucion({
      reto_id: retoId,
      usuario_id: req.usuarioId,
      codigo_o_link: codigoOLink,
      archivos: archivosJSON,
      metricas: metricas ? JSON.stringify(metricas) : null,
      estado: 'en_revision',
      puntuacion,
      rango_letra: rango.letra,
      informe,
      probabilidad_ia: evaluacion.probabilidadIA || 0,
      enviado_en: ahora,
      evaluado_en: null, // se llena cuando la empresa decide
    });

    dbOp.crearAlerta({
      usuarioId: req.usuarioId,
      tipo: 'noticia',
      texto: `Solución enviada a "${reto.titulo}". El motor la evaluó y está EN REVISIÓN por la empresa.`,
    });

    const UMBRAL_ENVIO_AUTOMATICO = 750;
    const envioAutomatico = puntuacion >= UMBRAL_ENVIO_AUTOMATICO;
    if (envioAutomatico) {
      dbOp.crearAlerta({
        usuarioId: req.usuarioId,
        tipo: 'noticia',
        texto: `Tu solución para "${reto.titulo}" superó los ${UMBRAL_ENVIO_AUTOMATICO} puntos (${puntuacion}/1,000) y fue ENVIADA AUTOMÁTICAMENTE a ${reto.empresa_nombre || 'la empresa que emitió el problema'}.`,
      });
    }

    const { informe: _i, ...solucionVisible } = solucion;
    return res.status(201).json({
      solucion: { ...solucionVisible, estado: 'en_revision' },
      mensaje: 'Solución analizada por el Motor Heurístico.',
      evaluacion: {
        puntuacion,
        rango: rango.letra,
        probabilidadIA: evaluacion.probabilidadIA || 0,
        nivelIA: evaluacion.nivelIA || 'humano',
        envioAutomatico,
        umbral: UMBRAL_ENVIO_AUTOMATICO,
        empresaNombre: nombreEmpresa,
      },
    });
  } catch (error) {
    console.error('Error en POST /api/soluciones:', error);
    return res.status(500).json({ error: 'No se pudo evaluar la solución.' });
  }
});

app.post('/api/soluciones/:id/decision', requireEmpresa, (req, res) => {
  try {
    const { decision, comentario } = req.body || {};
    if (decision !== 'aprobado' && decision !== 'rechazado') {
      return res.status(400).json({ error: 'Decisión inválida: usa "aprobado" o "rechazado".' });
    }
    if (comentario && String(comentario).length > 2000) {
      return res.status(400).json({ error: 'El comentario no puede superar los 2,000 caracteres.' });
    }
    const solucion = dbOp.obtenerSolucion(req.params.id);
    if (!solucion) return res.status(404).json({ error: 'Esa solución no existe.' });
    const reto = dbOp.obtenerReto(solucion.reto_id);
    if (!reto || reto.empresa_id !== req.empresaId) {
      return res.status(403).json({ error: 'Esa solución no pertenece a tu empresa.' });
    }
    if (solucion.estado !== 'en_revision') {
      if (solucion.estado === decision) {
        return res.json({ solucion, repetida: true });
      }
      return res.status(409).json({
        error:
          solucion.estado === 'aprobado'
            ? 'Esa solución ya fue APROBADA antes. No se puede cambiar la decisión.'
            : 'Esa solución ya fue NO APROBADA antes. No se puede cambiar la decisión.',
      });
    }

    const actualizada = dbOp.decisionSolucion(req.params.id, decision, new Date().toISOString());

    const puntos = Number(solucion.puntuacion || 0);
    const rango = motor.obtenerRangoPorPuntuacion(puntos);
    if (decision === 'rechazado') {
      const textoEmpresa = String(comentario || '').trim();
      dbOp.crearAlerta({
        usuarioId: solucion.usuario_id,
        tipo: 'cooldown',
        texto: `NO APROBADA: tu solución para "${reto.titulo}" obtuvo ${puntos}/1,000 (Nivel ${rango.letra}). ${solucion.informe || ''}${textoEmpresa ? `\n\nMENSAJE DE LA EMPRESA: ${textoEmpresa}` : ''}`.trim(),
      });
    } else if (puntos >= 900) {
      dbOp.crearAlerta({
        usuarioId: solucion.usuario_id,
        tipo: 'boveda',
        texto: `APROBADA y en la Bóveda de Talento: "${reto.titulo}" con ${puntos}/1,000 (Nivel ${rango.letra}). ¡Las empresas ya pueden verte!`,
      });
    } else {
      dbOp.crearAlerta({
        usuarioId: solucion.usuario_id,
        tipo: 'prestigio',
        texto: `APROBADA: "${reto.titulo}" con ${puntos}/1,000 (Nivel ${rango.letra}). ${solucion.informe || ''}`.trim(),
      });
    }

    return res.json({ solucion: actualizada });
  } catch (error) {
    console.error('Error en POST /api/soluciones/:id/decision:', error);
    return res.status(500).json({ error: 'No se pudo registrar la decisión.' });
  }
});

app.get('/api/soluciones/mias', requireEstudiante, (req, res) => {
  try {
    let soluciones = dbOp.listarSolucionesDeUsuario(req.usuarioId);
    soluciones = soluciones.map((s) => s.estado === 'en_revision'
      ? { ...s, puntuacion: null, rango_letra: null, informe: null }
      : s);
    return res.json({ soluciones });
  } catch (error) {
    console.error('Error en GET /api/soluciones/mias:', error);
    return res.status(500).json({ error: 'No se pudieron cargar tus soluciones.' });
  }
});

app.get('/api/soluciones/:id/detalle', requireEstudiante, (req, res) => {
  try {
    const solucion = dbOp.obtenerSolucion(req.params.id);
    if (!solucion || solucion.usuario_id !== req.usuarioId) {
      return res.status(404).json({ error: 'Esa solución no existe o no es tuya.' });
    }
    const reto = dbOp.obtenerReto(solucion.reto_id);
    let salida = { ...solucion, reto_titulo: reto ? reto.titulo : null };
    if (solucion.estado === 'en_revision') {
      salida = { ...salida, puntuacion: null, rango_letra: null, informe: null };
    }
    return res.json({ solucion: salida });
  } catch (error) {
    console.error('Error en GET /api/soluciones/:id/detalle:', error);
    return res.status(500).json({ error: 'No se pudo cargar la solución.' });
  }
});

app.post('/api/seguimientos', requireEstudiante, (req, res) => {
  const { empresaId } = req.body || {};
  if (!empresaId) return res.status(400).json({ error: 'Falta la empresa a seguir.' });
  dbOp.seguirEmpresa(req.usuarioId, empresaId);
  return res.status(201).json({ mensaje: 'Ahora sigues a esta empresa.' });
});

app.delete('/api/seguimientos/:empresaId', requireEstudiante, (req, res) => {
  dbOp.dejarDeSeguir(req.usuarioId, req.params.empresaId);
  return res.json({ mensaje: 'Dejaste de seguir a esta empresa.' });
});

app.get('/api/seguimientos/mios', requireEstudiante, (req, res) => {
  return res.json({ empresas: dbOp.listarSeguidasPorUsuario(req.usuarioId) });
});

app.post('/api/reacciones', requireEstudiante, (req, res) => {
  const { tipoObjeto, objetoId } = req.body || {};
  if (!['reto', 'solucion'].includes(tipoObjeto) || !objetoId) {
    return res.status(400).json({ error: 'Reacción inválida.' });
  }
  dbOp.reaccionar(req.usuarioId, tipoObjeto, objetoId);
  return res.status(201).json({ total: dbOp.contarReacciones(tipoObjeto, objetoId) });
});

app.delete('/api/reacciones', requireEstudiante, (req, res) => {
  const { tipoObjeto, objetoId } = req.body || {};
  dbOp.quitarReaccion(req.usuarioId, tipoObjeto, objetoId);
  return res.json({ total: dbOp.contarReacciones(tipoObjeto, objetoId) });
});

app.get('/api/alertas/mias', requireEstudiante, (req, res) => {
  return res.json({ alertas: dbOp.listarAlertasDeUsuario(req.usuarioId) });
});

app.post('/api/alertas/:id/leer', requireEstudiante, (req, res) => {
  dbOp.marcarAlertaLeida(req.params.id, req.usuarioId);
  return res.json({ mensaje: 'Marcada como leída.' });
});

app.post('/api/alertas/:id/descartar', requireEstudiante, (req, res) => {
  dbOp.eliminarAlerta(req.params.id, req.usuarioId);
  return res.json({ mensaje: 'Notificación descartada.' });
});

const clientesSSE = new Map(); // clave: 'u:<id>' | 'e:<id>' → Set de objetos res

function enviarSSE(clave, evento) {
  const set = clientesSSE.get(clave);
  if (!set) return;
  const linea = `data: ${JSON.stringify(evento)}\n\n`;
  for (const res of set) {
    try { res.write(linea); } catch (_e) { set.delete(res); }
  }
}

const crearAlertaOriginal = dbOp.crearAlerta.bind(dbOp);
dbOp.crearAlerta = (datos) => {
  const resultado = crearAlertaOriginal(datos);
  if (datos.usuarioId) {
    enviarSSE(`u:${datos.usuarioId}`, { tipo: 'alerta', alerta: { tipo: datos.tipo, texto: datos.texto, creado_en: Date.now() } });
  }
  if (datos.empresaId) {
    enviarSSE(`e:${datos.empresaId}`, { tipo: 'alerta', alerta: { tipo: datos.tipo, texto: datos.texto, creado_en: Date.now() } });
  }
  return resultado;
};

app.get('/api/eventos', (req, res) => {
  const token = String(req.query.token || '');
  let clave = null;
  try {
    const datos = jwt.verify(token, JWT_SECRET); // token de estudiante (sub = uid)
    if (datos && datos.sub) clave = `u:${datos.sub}`;
  } catch (_e) { /* token de estudiante inválido */ }
  if (!clave) {
    try {
      const datos = jwt.verify(token, JWT_SECRET);
      if (datos && datos.sub) clave = `u:${datos.sub}`;
    } catch (_e2) { /* sin sesión */ }
  }
  if (!clave) return res.status(401).json({ error: 'Token inválido para el canal de eventos.' });

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'Access-Control-Allow-Origin': '*',
  });
  res.write(': conectado\n\n');

  if (!clientesSSE.has(clave)) clientesSSE.set(clave, new Set());
  const set = clientesSSE.get(clave);
  set.add(res);

  const ping = setInterval(() => {
    try { res.write(': ping\n\n'); } catch (_e) { /* reconectará solo */ }
  }, 25000);

  req.on('close', () => {
    clearInterval(ping);
    set.delete(res);
    if (!set.size) clientesSSE.delete(clave);
  });
});

const HOST_BIND = process.env.BIND_HOST || (API_REMOTA_HABILITADA ? '0.0.0.0' : '127.0.0.1');
app.listen(PUERTO, HOST_BIND, () => {
  const alcance = API_REMOTA_HABILITADA ? 'acceso remoto habilitado' : 'solo equipo local';
  console.log(`SkillBridge API escuchando en http://${HOST_BIND}:${PUERTO} (${alcance})`);
});
