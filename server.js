const path = require('path');
const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const cors = require('cors');
const mercadopago = require('mercadopago');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
// Configure Mercado Pago SDK if access token is provided
try {
    if (process.env.MERCADOPAGO_ACCESS_TOKEN) {
        mercadopago.configure({ access_token: process.env.MERCADOPAGO_ACCESS_TOKEN });
        console.log('Mercado Pago SDK configured');
    } else {
        console.log('Mercado Pago ACCESS_TOKEN not configured; SDK disabled');
    }
} catch (e) {
    console.warn('Failed to configure Mercado Pago SDK', e && e.message ? e.message : e);
}
app.post('/api/mercadopago/webhook', express.json(), async (req, res) => {
    try {
        const body = req.body || {};
        // Try to extract a resource id or payer email
        const resourceId = body && (body.id || (body.data && body.data.id)) ? (body.id || (body.data && body.data.id)) : null;

        // Helper to fetch MP resource when access token is available
        async function fetchMpResource(path) {
            if (!process.env.MERCADOPAGO_ACCESS_TOKEN) return null;
            const token = process.env.MERCADOPAGO_ACCESS_TOKEN;
            const https = require('https');
            const url = `https://api.mercadopago.com${path}`;
            return await new Promise((resolve, reject) => {
                const opts = { headers: { Authorization: `Bearer ${token}` } };
                https.get(url, opts, (r) => {
                    let data = '';
                    r.on('data', c => data += c);
                    r.on('end', () => {
                        try { resolve(JSON.parse(data)); } catch (e) { resolve(null); }
                    });
                }).on('error', (e) => resolve(null));
            });
        }

        let mpData = null;
        if (resourceId && process.env.MERCADOPAGO_ACCESS_TOKEN) {
            // Try payments endpoint first
            mpData = await fetchMpResource(`/v1/payments/${encodeURIComponent(resourceId)}`);
            if (!mpData) mpData = await fetchMpResource(`/preapproval/${encodeURIComponent(resourceId)}`);
            if (!mpData) mpData = await fetchMpResource(`/v1/subscriptions/${encodeURIComponent(resourceId)}`);
        }

        // Fallback: try to extract payer email from webhook body
        const payerEmail = (mpData && mpData.payer && mpData.payer.email) ? mpData.payer.email : (body && body.payer && body.payer.email ? body.payer.email : (body && body.data && body.data.payer && body.data.payer.email ? body.data.payer.email : null));

        if (!payerEmail) {
            console.warn('MP webhook received but no payer email found; ignoring');
            return res.json({ ok: true });
        }

        const email = String(payerEmail).toLowerCase();

        // Find pending subscription for this email
        const sub = await db.collection('subscriptions').findOne({ email, status: { $in: ['pending', 'pending_payment'] } });
        if (!sub) {
            console.warn('MP webhook: no pending subscription found for', email);
            return res.json({ ok: true });
        }

        // Update subscription as active and store mp info
        const mpInfo = mpData || body;
        const updateFields = { status: 'active', activatedAt: new Date(), mp_raw: mpInfo };
        // store any id found
        const possibleId = (mpInfo && (mpInfo.id || mpInfo.subscription_id || mpInfo.preapproval_id || mpInfo.recurring_payment_id)) || null;
        if (possibleId) updateFields['mp.subscription_id'] = possibleId;

        await db.collection('subscriptions').updateOne({ _id: sub._id }, { $set: updateFields });

        // Create admin user if not exists
        const existing = await db.collection('users').findOne({ email });
        if (!existing) {
            const newUser = {
                email: email,
                password: sub.hashedPassword || null,
                role: 'administrador',
                gymId: null,
                name: sub.gymName || null,
                phone: sub.phone || null,
                createdAt: new Date()
            };
            await db.collection('users').insertOne(newUser);
            console.log('Admin user created after MP webhook for', email);
        } else {
            console.log('Admin user already exists for', email);
        }

        return res.json({ ok: true });
    } catch (err) {
        console.error('Error processing MP webhook', err && err.message ? err.message : err);
        return res.status(500).json({ error: 'Error processing webhook' });
    }
});

// Return page after Mercado Pago checkout (optional redirect target)
app.get('/mp-return', async (req, res) => {
    try {
        const email = req.query.email || null;
        if (!email) return res.status(400).send('email query param required');
        const normalized = String(email).toLowerCase();
        // Find user and ensure subscription active
        const sub = await db.collection('subscriptions').findOne({ email: normalized, status: 'active' });
        if (!sub) {
            return res.send(`<html><body><h3>Pago recibido, pero la suscripción aún no está activa. Esperá unos minutos e intentá ingresar nuevamente.</h3></body></html>`);
        }
        // Ensure user exists
        let user = await db.collection('users').findOne({ email: normalized });
        if (!user) {
            // create user
            const newUser = { email: normalized, password: sub.hashedPassword || null, role: 'administrador', gymId: null, name: sub.gymName || null, phone: sub.phone || null, createdAt: new Date() };
            const r = await db.collection('users').insertOne(newUser);
            user = await db.collection('users').findOne({ _id: r.insertedId });
        }

        const token = generateToken(user);
        // Return a small page that sets token in localStorage and redirects to admin panel
        res.setHeader('Content-Type', 'text/html');
        return res.send(`<!doctype html><html><body><script>try{localStorage.setItem('token','${token}');location.href='/administrador.html';}catch(e){document.write('Error redirigiendo: '+e.message);}</script></body></html>`);
    } catch (e) {
        console.error('Error in /mp-return', e && e.message ? e.message : e);
        return res.status(500).send('error');
    }
});

// Create a subscription record for a Mercado Pago subscription-plan link
app.post('/api/mercadopago/create-subscription-plan', async (req, res) => {
    try {
        const { gymName, phone, email, password, planUrl } = req.body || {};
        if (!gymName || !email || !password || !planUrl) return res.status(400).json({ error: 'gymName, email, password y planUrl son requeridos' });

        const normalizedEmail = String(email).toLowerCase();
        const hashed = await bcrypt.hash(String(password), 10);

        const subDoc = {
            email: normalizedEmail,
            gymName,
            phone: phone || null,
            hashedPassword: hashed,
            planUrl,
            status: 'pending_payment',
            createdAt: new Date(),
            mp: { plan_link: planUrl }
        };

        const r = await db.collection('subscriptions').insertOne(subDoc);
        const subId = r.insertedId.toString();

        // Try to build a return URL so MP can redirect after checkout (best-effort)
        const returnUrl = `${APP_BASE_URL}/mp-return?email=${encodeURIComponent(normalizedEmail)}`;
        let checkoutUrl = planUrl;

        // If we have an access token, try to create a preapproval subscription using the SDK
        const mpToken = process.env.MERCADOPAGO_ACCESS_TOKEN || null;
        try {
            // Attempt to extract a preapproval_plan_id from the provided plan URL
            let planId = null;
            try {
                const u = new URL(planUrl);
                planId = u.searchParams.get('preapproval_plan_id') || u.searchParams.get('preapproval_plan_id');
            } catch (e) { /* ignore URL parse errors */ }

            if (mpToken && planId) {
                // Try SDK call first (if mercadopago.post is available)
                let mpResp = null;
                try {
                    if (mercadopago && typeof mercadopago.post === 'function') {
                        const body = {
                            payer_email: normalizedEmail,
                            preapproval_plan_id: planId,
                            back_url: returnUrl,
                            reason: `Membresía ${gymName || 'cliente'}`
                        };
                        mpResp = await mercadopago.post('/preapproval_subscriptions', body);
                        // SDK may return various shapes
                        checkoutUrl = (mpResp && mpResp.response && mpResp.response.init_point) || (mpResp && mpResp.init_point) || (mpResp && mpResp.body && mpResp.body.init_point) || checkoutUrl;
                        // store mp ids if available
                        const mpId = (mpResp && ((mpResp.response && mpResp.response.id) || mpResp.id || (mpResp.body && mpResp.body.id))) || null;
                        if (mpId) {
                            await db.collection('subscriptions').updateOne({ _id: r.insertedId }, { $set: { 'mp.preapproval_subscription_id': String(mpId) } });
                        }
                    } else {
                        // Fallback: direct HTTPS call to MP REST API
                        const https = require('https');
                        const payload = JSON.stringify({ payer_email: normalizedEmail, preapproval_plan_id: planId, back_url: returnUrl, reason: `Membresía ${gymName || 'cliente'}` });
                        const opts = {
                            hostname: 'api.mercadopago.com',
                            path: '/preapproval_subscriptions',
                            method: 'POST',
                            headers: {
                                'Authorization': `Bearer ${mpToken}`,
                                'Content-Type': 'application/json',
                                'Content-Length': Buffer.byteLength(payload)
                            }
                        };
                        mpResp = await new Promise((resolve, reject) => {
                            const reqMp = https.request(opts, (resMp) => {
                                let data = '';
                                resMp.on('data', c => data += c);
                                resMp.on('end', () => {
                                    try { resolve(JSON.parse(data)); } catch (e) { resolve(null); }
                                });
                            });
                            reqMp.on('error', (e) => resolve(null));
                            reqMp.write(payload);
                            reqMp.end();
                        });
                        if (mpResp) {
                            checkoutUrl = mpResp.init_point || mpResp.initPoint || checkoutUrl;
                            if (mpResp.id) await db.collection('subscriptions').updateOne({ _id: r.insertedId }, { $set: { 'mp.preapproval_subscription_id': String(mpResp.id) } });
                        }
                    }
                } catch (e) {
                    console.warn('Error creando preapproval via MP SDK/REST:', e && e.message ? e.message : e);
                }
            }
        } catch (e) {
            console.warn('Error preparing Mercado Pago checkout:', e && e.message ? e.message : e);
        }

        // If we didn't get an init_point from MP, append a return_url to the original plan link (best-effort)
        if (!checkoutUrl || checkoutUrl === planUrl) {
            if (planUrl.indexOf('?') === -1) checkoutUrl = `${planUrl}?return_url=${encodeURIComponent(returnUrl)}`;
            else checkoutUrl = `${planUrl}&return_url=${encodeURIComponent(returnUrl)}`;
        }

        return res.json({ ok: true, subId, checkoutUrl });
    } catch (err) {
        console.error('Error creating plan-based subscription', err && err.message ? err.message : err);
        return res.status(500).json({ error: 'Error creando suscripción' });
    }
});

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017';
// Optional fallback URI (useful for local development if Atlas SRV fails due to TLS/OpenSSL issues)
const FALLBACK_MONGO_URI = process.env.FALLBACK_MONGO_URI || process.env.LOCAL_MONGO_URI || 'mongodb://localhost:27017';
// Connection tuning from env
const MONGO_CONNECT_MAX_RETRIES = Number(process.env.MONGO_CONNECT_MAX_RETRIES || 5);
const MONGO_CONNECT_RETRY_MS = Number(process.env.MONGO_CONNECT_RETRY_MS || 5000);
const MONGO_TLS_ALLOW_INVALID = process.env.MONGO_TLS_ALLOW_INVALID === '1' || process.env.MONGO_TLS_ALLOW_INVALID === 'true';
const MONGO_TLS_CA_FILE = process.env.MONGO_TLS_CA_FILE || null;
const DB_NAME = process.env.DB_NAME || 'pilatesdb';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change';

// SMTP / App config for password reset emails
const SMTP_HOST = process.env.SMTP_HOST || null;
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_SECURE = process.env.SMTP_SECURE === '1' || process.env.SMTP_SECURE === 'true';
const SMTP_USER = process.env.SMTP_USER || null;
const SMTP_PASS = process.env.SMTP_PASS || null;
const APP_BASE_URL = (process.env.APP_BASE_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/$/, '');

let mailTransporter = null;
if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
    try {
        mailTransporter = nodemailer.createTransport({ host: SMTP_HOST, port: SMTP_PORT, secure: SMTP_SECURE, auth: { user: SMTP_USER, pass: SMTP_PASS } });
        // verify transporter asynchronously
        mailTransporter.verify().then(() => console.log('SMTP transporter ready')).catch(err => console.warn('SMTP verify failed:', err && err.message ? err.message : err));
    } catch (e) {
        console.warn('Failed to create SMTP transporter', e && e.message ? e.message : e);
        mailTransporter = null;
    }
} else {
    console.log('SMTP not configured. Password reset links will be logged to console.');
}

// Configuración por defecto del gimnasio
const DEFAULT_GYM_CONFIG = {
    minCancellationHours: 24,
    creditExpirationDays: 30,
    autoCancelDueOverdueDays: 7,
    maxCredits: 10
};

let db;

// Server-Sent Events clients
const sseClients = new Set();

function sendSseEvent(type, payload, targetGymId = null) {
    const msg = `data: ${JSON.stringify({ type, payload })}\n\n`;
    for (const client of Array.from(sseClients)) {
        try {
            // If targetGymId is specified, only send to clients matching that gym
            if (targetGymId && client.gymId && String(client.gymId) !== String(targetGymId)) continue;
            client.res.write(msg);
        } catch (e) {
            // remove problematic client
            try { client.res.end(); } catch (er) { }
            sseClients.delete(client);
        }
    }
}

async function connectDB() {
    // Build mongo options with optional TLS flags from env
    const mongoOptions = { 
        useUnifiedTopology: true,
        // For production, we might need to allow invalid certificates in some environments
        tlsAllowInvalidCertificates: process.env.NODE_ENV !== 'production',
        retryWrites: true,
        w: 'majority'
    };
    if (MONGO_TLS_ALLOW_INVALID) mongoOptions.tlsAllowInvalidCertificates = true;
    if (MONGO_TLS_CA_FILE) mongoOptions.tlsCAFile = MONGO_TLS_CA_FILE;

    // Extract database name from URI if present, otherwise use DB_NAME env var
    let dbName = DB_NAME;
    try {
        const uriMatch = MONGO_URI.match(/\.net\/([^?]+)/);
        if (uriMatch && uriMatch[1]) {
            dbName = uriMatch[1];
            console.log('Using database name from URI:', dbName);
        }
    } catch (e) {
        console.log('Could not extract DB name from URI, using env var:', dbName);
    }

    let lastErr = null;
    for (let attempt = 1; attempt <= MONGO_CONNECT_MAX_RETRIES; attempt++) {
        try {
            const client = new MongoClient(MONGO_URI, mongoOptions);
            await client.connect();
            db = client.db(dbName);
            console.log('Connected to MongoDB', MONGO_URI, dbName);
            return;
        } catch (err) {
            lastErr = err;
            const msg = err && err.message ? err.message : String(err);
            if (process.env.DEBUG_MONGO) console.error(`Mongo connect attempt ${attempt} failed:`, msg, err);
            else console.warn(`Mongo connect attempt ${attempt} failed: ${msg}`);

            if (attempt < MONGO_CONNECT_MAX_RETRIES) {
                console.log(`Retrying in ${MONGO_CONNECT_RETRY_MS}ms... (${attempt}/${MONGO_CONNECT_MAX_RETRIES})`);
                await new Promise(r => setTimeout(r, MONGO_CONNECT_RETRY_MS));
                continue;
            }
            // fall through to fallback attempt
        }
    }

    // If primary failed after retries, try fallback
    if (FALLBACK_MONGO_URI && FALLBACK_MONGO_URI !== MONGO_URI) {
        try {
            console.log(`Attempting fallback Mongo connection to ${FALLBACK_MONGO_URI}...`);
            const fallbackOptions = Object.assign({}, mongoOptions);
            const fallbackClient = new MongoClient(FALLBACK_MONGO_URI, fallbackOptions);
            await fallbackClient.connect();
            db = fallbackClient.db(DB_NAME);
            console.log('Connected to MongoDB using fallback URI', FALLBACK_MONGO_URI, DB_NAME);
            return;
        } catch (err2) {
            lastErr = err2;
            if (process.env.DEBUG_MONGO) console.error('Fallback Mongo connection failed:', err2);
            else console.warn('Fallback Mongo connection failed.');
        }
    }

    // If we reached here, all connection attempts failed
    const err = lastErr || new Error('Unknown Mongo connection error');
    // Print a concise warning by default (the raw OpenSSL stack is noisy on Windows);
    // if you need diagnostics, set DEBUG_MONGO=1 in the environment to see the full error.
    const primaryErrMsg = err && err.message ? err.message : String(err);
    if (process.env.DEBUG_MONGO) {
        console.error('Primary Mongo connection failed:', primaryErrMsg, err);
    } else {
        console.warn('Primary Mongo connection failed (TLS/SSL). Will attempt fallback if configured.');
        console.warn('To see the full error set DEBUG_MONGO=1 and restart the server.');
    }

    // If the primary URI is an Atlas SRV and we have a fallback, try it and give the developer guidance
    if (FALLBACK_MONGO_URI && FALLBACK_MONGO_URI !== MONGO_URI) {
        console.log(`Attempting fallback Mongo connection to ${FALLBACK_MONGO_URI}...`);
        try {
            const fallbackClient = new MongoClient(FALLBACK_MONGO_URI, { useUnifiedTopology: true });
            await fallbackClient.connect();
            db = fallbackClient.db(DB_NAME);
            console.log('Connected to MongoDB using fallback URI', FALLBACK_MONGO_URI, DB_NAME);
            return;
        } catch (err2) {
            console.error('Fallback Mongo connection also failed:', err2 && err2.message ? err2.message : err2);
            // fall through to final error handling below
        }
    }

    // Provide actionable hints for the developer when TLS/SSL errors occur with Atlas
    if (err && err.message && /SSL|tls|TLS|certificate|alert/i.test(err.message)) {
        console.error('\nDetected an SSL/TLS error when connecting to MongoDB Atlas. Common causes and fixes:');
        console.error('- Your Node/OpenSSL build may be incompatible with Atlas SRV TLS. Try upgrading Node or OpenSSL.');
        console.error("- For local development, set FALLBACK_MONGO_URI or LOCAL_MONGO_URI to 'mongodb://localhost:27017' and run a local mongod instance.");
        console.error('- Ensure your environment allows outbound TLS connections to Atlas (firewall, proxy, corporate network).');
        console.error('- If you intentionally want to use Atlas, try connecting from a machine with updated crypto libraries.');
        if (!MONGO_TLS_ALLOW_INVALID) console.error("Tip: for local debugging you can set MONGO_TLS_ALLOW_INVALID=true in your .env to bypass strict cert checks (not for production).");
    }

    // Throw the last error so caller can decide. Higher-level code may choose to start a degraded server instead of exiting.
    throw err;

    // Asegurar que existe la configuración del gimnasio
    const gym = await db.collection('gyms').findOne({});
    if (!gym) {
        await db.collection('gyms').insertOne({
            ...DEFAULT_GYM_CONFIG,
            createdAt: new Date()
        });
    }
}

function generateToken(user) {
    const payload = { id: user._id.toString(), role: user.role };
    if (user.dni) payload.dni = user.dni;
    if (user.email) payload.email = user.email;
    if (user.gymId) payload.gymId = user.gymId;
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });
}

async function getUserByEmail(email) {
    return db.collection('users').findOne({ email: email });
}

async function getUserByDni(dni) {
    return db.collection('users').findOne({ dni: dni });
}

app.post('/api/login', async (req, res) => {
    const { dni } = req.body;
    console.log('[LOGIN] Received DNI:', dni, 'Type:', typeof dni);
    console.log('[LOGIN] DB connected:', !!db);
    if (!dni) return res.status(400).json({ error: 'DNI es requerido' });
    try {
        const user = await getUserByDni(dni);
        console.log('[LOGIN] User found:', !!user, user ? `(${user.name} - ${user.role})` : '');
        if (!user) {
            // Try to see what users exist
            const count = await db.collection('users').countDocuments();
            console.log('[LOGIN] Total users in DB:', count);
            return res.status(401).json({ error: 'Usuario no encontrado' });
        }
        const token = generateToken(user);
        res.json({ token, role: user.role });
    } catch (err) {
        console.error('[LOGIN] Error:', err);
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

// Admin login via email + password
app.post('/api/admin/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email y password son requeridos' });
    try {
        const user = await getUserByEmail(email);
        if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });
        // validar rol
        if (!['administrador', 'superusuario'].includes(user.role)) {
            return res.status(403).json({ error: 'No tiene permisos de administrador' });
        }
        if (!user.password) return res.status(401).json({ error: 'Usuario sin contraseña' });
        const ok = await bcrypt.compare(password, user.password);
        if (!ok) return res.status(401).json({ error: 'Credenciales incorrectas' });
        // If administrador, ensure they have an active subscription (except for test accounts)
        const testAccounts = ['adminpilates.local', 'admin@pilates.local'];
        if (user.role === 'administrador' && !testAccounts.includes(user.email)) {
            const sub = await db.collection('subscriptions').findOne({ email: String(user.email).toLowerCase(), status: 'active' });
            if (!sub) return res.status(403).json({ error: 'No tiene suscripción activa' });
        }
        const token = generateToken(user);
        res.json({ token, role: user.role });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

// Expose Google client ID to the frontend (optional)
app.get('/api/auth/google/client-id', async (req, res) => {
    try {
        const clientId = process.env.GOOGLE_CLIENT_ID || null;
        res.json({ clientId });
    } catch (err) {
        console.error('Error returning google client id', err);
        res.status(500).json({ clientId: null });
    }
});

// Login with Google ID token (issued by Google Identity Services)
app.post('/api/auth/google', async (req, res) => {
    const { idToken } = req.body || {};
    if (!idToken) return res.status(400).json({ error: 'idToken requerido' });

    try {
        // Verify token with Google's tokeninfo endpoint
        const tokenInfoUrl = 'https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(idToken);
        let info = null;
        if (typeof fetch === 'function') {
            const r = await fetch(tokenInfoUrl);
            if (!r.ok) return res.status(401).json({ error: 'Token inválido' });
            info = await r.json();
        } else {
            // fallback to https
            info = await new Promise((resolve, reject) => {
                const https = require('https');
                https.get(tokenInfoUrl, (r) => {
                    let data = '';
                    r.on('data', chunk => data += chunk);
                    r.on('end', () => {
                        try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
                    });
                }).on('error', reject);
            });
        }

        // Basic checks
        const email = info && (info.email || info.email_verified && info.email) ? info.email : null;
        const aud = info && info.aud ? info.aud : null;
        const emailVerified = info && (info.email_verified === 'true' || info.email_verified === true);

        const expectedAud = process.env.GOOGLE_CLIENT_ID || null;
        if (expectedAud && aud && String(aud) !== String(expectedAud)) {
            console.warn('Google token aud mismatch', { aud, expectedAud });
            return res.status(401).json({ error: 'Token no válido para esta aplicación' });
        }
        if (!email || !emailVerified) return res.status(401).json({ error: 'Email no verificado por Google' });

        // Find user by email
        const user = await db.collection('users').findOne({ email: String(email).toLowerCase() });
        if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });
        if (!['administrador', 'superusuario'].includes(user.role)) return res.status(403).json({ error: 'No tiene permisos de administrador' });

        const token = generateToken(user);
        res.json({ token, role: user.role });
    } catch (err) {
        console.error('Error verifying google token', err && err.message ? err.message : err);
        res.status(500).json({ error: 'Error verificando token de Google' });
    }
});

app.get('/api/me', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }

    // Attempt to fetch user details from DB to include name/lastName/email in /api/me
    try {
        if (!db) return res.json({ id: payload.id, role: payload.role, dni: payload.dni, gymId: payload.gymId });
        const user = await db.collection('users').findOne({ _id: new ObjectId(payload.id) }, { projection: { password: 0 } });
        if (!user) return res.json({ id: payload.id, role: payload.role, dni: payload.dni, gymId: payload.gymId });
        return res.json({ id: payload.id, role: payload.role, dni: payload.dni, gymId: payload.gymId, name: user.name || null, lastName: user.lastName || null, email: user.email || null });
    } catch (err) {
        console.warn('Failed to load full user for /api/me, returning token payload only', err && err.message ? err.message : err);
        return res.json({ id: payload.id, role: payload.role, dni: payload.dni, gymId: payload.gymId });
    }
});

// Password reset: request a reset (sends email with token link)
app.post('/api/password-reset/request', async (req, res) => {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'Email requerido' });
    try {
        // normalize
        const user = await getUserByEmail(String(email).toLowerCase());
        // For privacy, always return 200 even if user not found
        if (!user) {
            return res.json({ ok: true });
        }

        const token = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + (60 * 60 * 1000)); // 1 hour

        await db.collection('password_resets').insertOne({ userId: user._id, token, expiresAt, used: false, createdAt: new Date() });

        const resetLink = `${APP_BASE_URL}/password-reset?token=${token}`;

        if (mailTransporter) {
            const mailOpts = {
                from: SMTP_USER,
                to: user.email,
                subject: 'Restablecer contraseña',
                text: `Ingresá al siguiente enlace para restablecer tu contraseña:\n\n${resetLink}\n\nSi no solicitaste este correo, ignoralo.`,
                html: `<p>Ingresá al siguiente enlace para restablecer tu contraseña:</p><p><a href="${resetLink}">${resetLink}</a></p><p>Si no solicitaste este correo, ignoralo.</p>`
            };
            try {
                await mailTransporter.sendMail(mailOpts);
            } catch (e) {
                console.error('Error sending password reset email', e && e.message ? e.message : e);
                // fallback to logging
                console.log('Password reset link (fallback):', resetLink);
            }
        } else {
            // Not configured: log link for developer/testing
            console.log('Password reset link for', user.email, resetLink);
        }

        return res.json({ ok: true });
    } catch (err) {
        console.error('Error in password reset request:', err && err.message ? err.message : err);
        return res.status(500).json({ error: 'Error procesando solicitud' });
    }
});

// Confirm password reset: accept token + newPassword
app.post('/api/password-reset/confirm', async (req, res) => {
    const { token, newPassword } = req.body || {};
    if (!token || !newPassword) return res.status(400).json({ error: 'Token y nueva contraseña requeridos' });
    try {
        const rec = await db.collection('password_resets').findOne({ token });
        if (!rec) return res.status(400).json({ error: 'Token inválido' });
        if (rec.used) return res.status(400).json({ error: 'Token ya utilizado' });
        if (rec.expiresAt && new Date(rec.expiresAt) < new Date()) return res.status(400).json({ error: 'Token expirado' });

        const hashed = await bcrypt.hash(newPassword, 10);
        await db.collection('users').updateOne({ _id: new ObjectId(rec.userId) }, { $set: { password: hashed } });
        await db.collection('password_resets').updateOne({ _id: rec._id }, { $set: { used: true, usedAt: new Date() } });

        return res.json({ ok: true });
    } catch (err) {
        console.error('Error confirming password reset', err && err.message ? err.message : err);
        return res.status(500).json({ error: 'Error actualizando contraseña' });
    }
});

// Minimal password reset page: serves a tiny form that POSTs to /api/password-reset/confirm
app.get('/password-reset', (req, res) => {
    const token = req.query.token || '';
    res.setHeader('Content-Type', 'text/html');
    res.send(`<!doctype html><html><head><meta charset="utf-8"><title>Restablecer contraseña</title></head><body style="font-family:Arial,Helvetica,sans-serif;padding:20px"><h2>Restablecer contraseña</h2><p>Completá la nueva contraseña:</p><div><input id="pw" type="password" placeholder="Nueva contraseña" style="padding:8px;width:320px;margin-bottom:8px"/></div><div><input id="pw2" type="password" placeholder="Confirmar contraseña" style="padding:8px;width:320px;margin-bottom:8px"/></div><div><button id="btn">Restablecer</button></div><div id="msg" style="margin-top:12px;color:#b91c1c"></div><script>document.getElementById('btn').addEventListener('click', async ()=>{const pw=document.getElementById('pw').value;const pw2=document.getElementById('pw2').value;const t='${token}';if(!pw||!pw2){document.getElementById('msg').textContent='Completá ambos campos';return;}if(pw!==pw2){document.getElementById('msg').textContent='Las contraseñas no coinciden';return;}try{const r=await fetch('/api/password-reset/confirm',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t,newPassword:pw})});const b=await r.json();if(!r.ok){document.getElementById('msg').textContent=b && b.error ? b.error : 'Error';return;}document.body.innerHTML='<div style="padding:20px;font-family:Arial,Helvetica,sans-serif"><h3>Contraseña restablecida</h3><p>Puedes cerrar esta ventana e ingresar con tu nueva contraseña.</p></div>';}catch(e){document.getElementById('msg').textContent='Error de red';}});</script></body></html>`);
});

// Middleware para verificar token y rol admin/superusuario
async function authMiddleware(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        if (!['administrador', 'superusuario'].includes(payload.role)) {
            return res.status(403).json({ error: 'No tienes permisos' });
        }
        // Attach user payload (including gymId if present). If gymId is missing
        // (older tokens), load it from the database synchronously (await) so
        // that downstream handlers see a complete req.user and avoid spurious 403s.
        req.user = payload;
        try {
            if (!req.user.gymId && req.user.id) {
                const u = await db.collection('users').findOne({ _id: new ObjectId(req.user.id) });
                if (u && u.gymId) req.user.gymId = u.gymId;
            }
        } catch (e) {
            console.warn('Failed to enrich user payload with gymId', e && e.message ? e.message : e);
        }
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }
}

// Middleware más ligero que solo verifica el token y adjunta payload en req.user
// Útil para endpoints donde cualquier usuario autenticado puede actuar (con cheques adicionales)
function authAny(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        req.user = payload;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }
}

// Helper to extract payload from Authorization header for routes that don't use authMiddleware
function verifyToken(req) {
    const auth = req.headers.authorization;
    if (!auth) throw new Error('No autorizado');
    const parts = auth.split(' ');
    if (parts.length !== 2) throw new Error('Token mal formado');
    const token = parts[1];
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (err) {
        throw new Error('Token inválido');
    }
}

// CRUD Salones (rooms)
app.get('/api/rooms', authMiddleware, async (req, res) => {
    try {
        // Admins see only their gym rooms; superusuario sees all
        const q = {};
        if (req.user.role !== 'superusuario') q.gymId = req.user.gymId;
        const rooms = await db.collection('rooms').find(q).toArray();
        res.json(rooms);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al listar salones' });
    }
});

// List users (opcionalmente filtrar por rol y búsqueda)
app.get('/api/users', authMiddleware, async (req, res) => {
    try {
        const { role, search } = req.query;
        let q = {};

        // Filtro por rol
        if (role) {
            q.role = role;
        }

        // Si no es superusuario, limitar por gym
        if (req.user.role !== 'superusuario') {
            q.gymId = req.user.gymId;
        }

        // Búsqueda por nombre, apellido o DNI
        if (search) {
            const searchRegex = new RegExp(search, 'i');
            q.$or = [
                { name: searchRegex },
                { lastName: searchRegex },
                { dni: searchRegex }
            ];
        }

        const users = await db.collection('users')
            .find(q)
            .project({ password: 0 })
            .sort({ lastName: 1, name: 1 })
            .toArray();

        res.json(users);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al listar usuarios' });
    }
});

// Obtener clases de un alumno (solo el propio alumno o admin/superusuario)
app.get('/api/students/:id/classes', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }

    const { id } = req.params;
    // Permitir si es admin/superusuario
    if (!['administrador', 'superusuario'].includes(payload.role) && payload.id !== id) {
        return res.status(403).json({ error: 'No tienes permisos para ver estas clases' });
    }

    try {
        const studentObjectId = new ObjectId(id);
        // Filtrar por gymId si el payload contiene gymId (admins) o para proteger multi-tenancy
        const q = { students: studentObjectId };
        if (payload.gymId) q.gymId = payload.gymId;
        const classes = await db.collection('classes').find(q).toArray();
        const populated = await Promise.all(classes.map(async c => {
            const room = c.roomId ? await db.collection('rooms').findOne({ _id: new ObjectId(c.roomId) }) : null;
            const professor = c.professorId ? await db.collection('users').findOne({ _id: new ObjectId(c.professorId) }) : null;
            const studentsCount = Array.isArray(c.students) ? c.students.length : 0;
            const capacity = room ? room.capacity : 0;
            return Object.assign({}, c, { roomName: room ? room.name : null, professorName: professor ? professor.name : null, camillasFree: Math.max(0, capacity - studentsCount) });
        }));
        res.json(populated);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al obtener clases del alumno' });
    }
});

// Obtener datos de un alumno (propio) o admin/superusuario
app.get('/api/students/:id', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }
    const { id } = req.params;
    if (!['administrador', 'superusuario'].includes(payload.role) && payload.id !== id) {
        return res.status(403).json({ error: 'No tienes permisos para ver este alumno' });
    }
    try {
        const _id = new ObjectId(id);
        const q = { _id, role: 'alumno' };
        if (payload.gymId) q.gymId = payload.gymId;
        const student = await db.collection('users').findOne(q, { projection: { password: 0 } });
        if (!student) return res.status(404).json({ error: 'Alumno no encontrado' });
        res.json(student);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al obtener alumno' });
    }
});

// Listado de clases con capacidad (abierto a cualquier usuario autenticado)
app.get('/api/classes/open', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    try {
        jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }
    try {
        // limit to gym if token contains gymId
        let q = {};
        const payload = verifyToken(req);
        if (payload.gymId) q.gymId = payload.gymId;
        const classes = await db.collection('classes').find(q).toArray();
        const populated = await Promise.all(classes.map(async c => {
            const room = c.roomId ? await db.collection('rooms').findOne({ _id: new ObjectId(c.roomId) }) : null;
            const professor = c.professorId ? await db.collection('users').findOne({ _id: new ObjectId(c.professorId) }) : null;
            const studentsCount = Array.isArray(c.students) ? c.students.length : 0;
            const capacity = room ? room.capacity : 0;
            return Object.assign({}, c, { roomName: room ? room.name : null, professorName: professor ? professor.name : null, camillasFree: Math.max(0, capacity - studentsCount) });
        }));
        res.json(populated);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al listar clases abiertas' });
    }
});

// Config pública del gimnasio (sin auth)
app.get('/api/gym/config/public', async (req, res) => {
    try {
        const config = await db.collection('gyms').findOne({});
        res.json(config || DEFAULT_GYM_CONFIG);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al obtener configuración pública' });
    }
});

// Obtener instancias de clase de un alumno (solo el propio alumno o admin/superusuario)
app.get('/api/students/:id/class-instances', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }

    const { id } = req.params;
    if (!['administrador', 'superusuario'].includes(payload.role) && payload.id !== id) {
        return res.status(403).json({ error: 'No tienes permisos para ver estas clases' });
    }

    try {
        const studentObjectId = new ObjectId(id);
        const now = new Date();

        // Determine upper bound: from now until (dueDate + autoCancelDueOverdueDays)
        // If the student has a dueDate, we limit instances to that window so the
        // UI shows classes until the grace period after quota expiration.
        let upperLimit = null;
        try {
            const userDoc = await db.collection('users').findOne({ _id: studentObjectId });
            const gym = await db.collection('gyms').findOne({}) || DEFAULT_GYM_CONFIG;
            const extraDays = (gym && gym.autoCancelDueOverdueDays) ? gym.autoCancelDueOverdueDays : DEFAULT_GYM_CONFIG.autoCancelDueOverdueDays;
            if (userDoc && userDoc.dueDate) {
                const venc = new Date(userDoc.dueDate);
                venc.setDate(venc.getDate() + Number(extraDays || 0));
                upperLimit = venc;
            }
        } catch (e) {
            console.warn('Warning: failed to compute dueDate upper limit for student class instances', e);
            upperLimit = null;
        }

        // Obtener instancias futuras donde el alumno está inscrito (acotadas por upperLimit si existe)
        const q = {
            students: studentObjectId,
            dateTime: { $gte: now },
            status: { $ne: 'cancelled' }
        };
        if (upperLimit) q.dateTime.$lte = upperLimit;
        if (payload.gymId) q.gymId = payload.gymId;
        const instances = await db.collection('classInstances')
            .find(q)
            .sort({ dateTime: 1 })
            .toArray();

        const populated = await Promise.all(instances.map(async inst => {
            const room = inst.roomId ? await db.collection('rooms').findOne({ _id: new ObjectId(inst.roomId) }) : null;
            const professor = inst.professorId ? await db.collection('users').findOne({ _id: new ObjectId(inst.professorId) }) : null;
            const studentsCount = Array.isArray(inst.students) ? inst.students.length : 0;
            const capacity = room ? room.capacity : 0;
            return {
                ...inst,
                roomName: room ? room.name : null,
                professorName: professor ? professor.name : null,
                camillasFree: Math.max(0, capacity - studentsCount)
            };
        }));

        // If caller requests debug info, include the computed upperLimit for visibility
        if (req.query && req.query.debug === '1') {
            return res.json({ upperLimit: upperLimit ? upperLimit.toISOString() : null, instances: populated });
        }

        res.json(populated);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al obtener instancias del alumno' });
    }
});

// Listar instancias disponibles para recuperar (abierto a cualquier usuario autenticado)
app.get('/api/class-instances/available', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    try {
        jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }

    try {
        const now = new Date();
        const payload = verifyToken(req);
        const q = { dateTime: { $gte: now }, status: 'scheduled' };
        if (payload.gymId) q.gymId = payload.gymId;
        const instances = await db.collection('classInstances')
            .find(q)
            .sort({ dateTime: 1 })
            .toArray();

        const populated = await Promise.all(instances.map(async inst => {
            const room = inst.roomId ? await db.collection('rooms').findOne({ _id: new ObjectId(inst.roomId) }) : null;
            const professor = inst.professorId ? await db.collection('users').findOne({ _id: new ObjectId(inst.professorId) }) : null;
            const studentsCount = Array.isArray(inst.students) ? inst.students.length : 0;
            const capacity = room ? room.capacity : 0;
            const camillasFree = Math.max(0, capacity - studentsCount);

            return {
                ...inst,
                roomName: room ? room.name : null,
                professorName: professor ? professor.name : null,
                camillasFree
            };
        }));

        // Solo devolver las que tienen capacidad
        res.json(populated.filter(p => p.camillasFree > 0));
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al listar instancias disponibles' });
    }
});

// Cancelar instancia para un alumno (genera un ticket de crédito)
app.post('/api/students/:id/cancel-instance/:instanceId', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }

    const { id, instanceId } = req.params;
    if (!['administrador', 'superusuario'].includes(payload.role) && payload.id !== id) {
        return res.status(403).json({ error: 'No tienes permisos para cancelar esta clase' });
    }

    try {
        const studentObjectId = new ObjectId(id);
        const instanceObjectId = new ObjectId(instanceId);

        const instance = await db.collection('classInstances').findOne({ _id: instanceObjectId });
        if (!instance) return res.status(404).json({ error: 'Instancia no encontrada' });

        // Ensure the instance belongs to the same gym as the requester (unless superusuario)
        if (payload.role !== 'superusuario' && instance.gymId && instance.gymId !== payload.gymId) {
            return res.status(403).json({ error: 'No tenés permisos para recuperar esta instancia' });
        }

        // Ensure the instance belongs to the same gym as the requester (unless superusuario)
        if (payload.role !== 'superusuario' && instance.gymId && instance.gymId !== payload.gymId) {
            return res.status(403).json({ error: 'No tenés permisos para cancelar esta instancia' });
        }

        if (!instance.students || !instance.students.some(sid => sid.toString() === id)) {
            return res.status(404).json({ error: 'El estudiante no está inscrito en esta instancia' });
        }

        // Obtener configuración del gimnasio correspondiente (si existe gymId en instancia o en payload)
        let gym = await db.collection('gyms').findOne({});
        try {
            const payload = payload || jwt.verify(token, JWT_SECRET);
            if (payload && payload.gymId) {
                const g = await db.collection('gyms').findOne({ gymId: payload.gymId });
                if (g) gym = g;
            }
        } catch (e) { }
        const now = new Date();
        const diffHours = (new Date(instance.dateTime) - now) / 36e5;

        let generateTicket = diffHours >= gym.minCancellationHours;

        // Remover estudiante de la instancia
        await db.collection('classInstances').updateOne(
            { _id: instanceObjectId },
            { $pull: { students: studentObjectId }, $set: { updatedAt: new Date() } }
        );

        let ticket = null;
        if (generateTicket) {
            const creditDays = gym.creditExpirationDays || DEFAULT_GYM_CONFIG.creditExpirationDays;
            ticket = {
                id: new ObjectId().toString(),
                instanceId: instanceId,
                instanceSnapshot: {
                    dateTime: instance.dateTime,
                    duration: instance.duration,
                    roomId: instance.roomId,
                    professorId: instance.professorId
                },
                createdAt: new Date(),
                expiresAt: new Date(Date.now() + creditDays * 24 * 60 * 60 * 1000),
                status: 'active'
            };

            await db.collection('users').updateOne(
                { _id: studentObjectId },
                { $push: { tickets: ticket }, $set: { updatedAt: new Date() } }
            );
        }

        res.json({ ticket, message: generateTicket ? 'Ticket generado' : 'Cancelación sin ticket (menos de ' + gym.minCancellationHours + 'hs)' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al cancelar instancia' });
    }
});

// Create a ticket for a student (force-create, used by client when backend didn't
// generate one automatically). This endpoint requires Authorization and can be
// called by the student themself or by admin/superusuario.
app.post('/api/students/:id/create-ticket', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }

    const { id } = req.params;
    const { classId, instanceId } = req.body || {};

    // Permission check
    if (!['administrador', 'superusuario'].includes(payload.role) && payload.id !== id) {
        return res.status(403).json({ error: 'No tienes permisos para crear ticket' });
    }

    try {
        const studentObjectId = new ObjectId(id);
        const gym = await db.collection('gyms').findOne({}) || DEFAULT_GYM_CONFIG;
        const creditDays = gym.creditExpirationDays || DEFAULT_GYM_CONFIG.creditExpirationDays;

        const ticket = {
            id: new ObjectId().toString(),
            classId: classId || null,
            instanceId: instanceId || null,
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + creditDays * 24 * 60 * 60 * 1000),
            status: 'active'
        };

        await db.collection('users').updateOne(
            { _id: studentObjectId },
            { $push: { tickets: ticket }, $set: { updatedAt: new Date() } }
        );

        res.json({ ticket });
    } catch (err) {
        console.error('Error creating ticket:', err);
        res.status(500).json({ error: 'Error al crear ticket' });
    }
});

// Recuperar una instancia usando un ticket
app.post('/api/students/:id/recover-instance/:instanceId', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }

    const { id, instanceId } = req.params;
    const { ticketId } = req.body;
    if (!ticketId) return res.status(400).json({ error: 'ticketId es requerido' });

    if (!['administrador', 'superusuario'].includes(payload.role) && payload.id !== id) {
        return res.status(403).json({ error: 'No tienes permisos para recuperar esta clase' });
    }

    try {
        const studentObjectId = new ObjectId(id);
        const instanceObjectId = new ObjectId(instanceId);

        const user = await db.collection('users').findOne({ _id: studentObjectId });
        if (!user) return res.status(404).json({ error: 'Alumno no encontrado' });

        const ticket = (user.tickets || []).find(t => t.id === ticketId);
        if (!ticket) return res.status(404).json({ error: 'Ticket no encontrado' });
        if (ticket.status !== 'active') return res.status(400).json({ error: 'Ticket ya fue usado o no está activo' });
        if (new Date(ticket.expiresAt) < new Date()) return res.status(400).json({ error: 'Ticket expirado' });

        const instance = await db.collection('classInstances').findOne({ _id: instanceObjectId });
        if (!instance) return res.status(404).json({ error: 'Instancia no encontrada' });

        const room = instance.roomId ? await db.collection('rooms').findOne({ _id: new ObjectId(instance.roomId) }) : null;
        const studentsCount = Array.isArray(instance.students) ? instance.students.length : 0;
        const capacity = room ? room.capacity : 0;
        if (studentsCount >= capacity) {
            return res.status(400).json({ error: 'La clase está llena' });
        }

        // Inscribir al alumno en la instancia
        await db.collection('classInstances').updateOne(
            { _id: instanceObjectId },
            { $push: { students: studentObjectId }, $set: { updatedAt: new Date() } }
        );

        // Marcar ticket como usado
        await db.collection('users').updateOne(
            { _id: studentObjectId, 'tickets.id': ticketId },
            { $set: { 'tickets.$.status': 'used', 'tickets.$.usedAt': new Date(), updatedAt: new Date() } }
        );

        try { sendSseEvent('classes', { action: 'studentAdded', classId: id, studentId }, req.user && req.user.gymId ? req.user.gymId : null); } catch (e) { }
        try { sendSseEvent('classes', { action: 'studentRemoved', classId: id, studentId }, req.user && req.user.gymId ? req.user.gymId : null); } catch (e) { }
        try { sendSseEvent('classes', { action: 'studentUpdated', studentId: id, classesAdded: classesToAdd, classesRemoved: classesToRemove }, req.user && req.user.gymId ? req.user.gymId : null); } catch (e) { }
        // fetch the updated config to include membershipTypes in the event
        try {
            const updatedConfig = gymId ? await db.collection('gyms').findOne({ gymId }) : await db.collection('gyms').findOne({});
            try { sendSseEvent('gymConfig', { membershipTypes: (updatedConfig && updatedConfig.membershipTypes) || [] }, gymId || null); } catch (e) { }
        } catch (e) { /* ignore */ }
        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al recuperar instancia con ticket' });
    }
});

// CRUD Alumnos
app.post('/api/students', authAny, async (req, res) => {
    const {
        dni, name, lastName, phone, emergencyContact,
        membershipType, dueDate, classIds = []
    } = req.body;

    // Validar campos requeridos
    if (!dni || !name || !lastName) {
        return res.status(400).json({ error: 'DNI, nombre y apellido son requeridos' });
    }

    try {
        // Verificar DNI duplicado
        const exists = await db.collection('users').findOne({ dni });
        if (exists) {
            return res.status(409).json({ error: 'Ya existe un usuario con ese DNI' });
        }

        // Si se especifican clases, validar capacidad
        if (classIds.length > 0) {
            const classes = await db.collection('classes').find({
                _id: { $in: classIds.map(id => new ObjectId(id)) }
            }).toArray();

            // Verificar que existan todas las clases
            if (classes.length !== classIds.length) {
                return res.status(400).json({ error: 'Una o más clases no existen' });
            }

            // Si el solicitante es un profesor, asegurar que las clases sean suyas y del mismo gimnasio
            if (req.user && req.user.role === 'profesor') {
                for (const clase of classes) {
                    if (clase.professorId && String(clase.professorId) !== String(req.user.id)) {
                        return res.status(403).json({ error: 'No tenés permisos para asignar alumnos a una clase que no es tuya' });
                    }
                    if (clase.gymId) {
                        if (req.user.gymId && String(clase.gymId) !== String(req.user.gymId)) {
                            return res.status(403).json({ error: 'No tenés permisos para asignar clases de otro gimnasio' });
                        }
                        if (!req.user.gymId) {
                            console.warn('[PERM] user has no gymId on profile while assigning student to class', { userId: req.user && req.user.id, classId: clase._id });
                        }
                    }
                }
            }

            // Verificar capacidad en cada clase
            for (const clase of classes) {
                const room = await db.collection('rooms').findOne({ _id: new ObjectId(clase.roomId) });
                if (!room) continue;

                const studentsCount = clase.students ? clase.students.length : 0;
                if (studentsCount >= room.capacity) {
                    return res.status(400).json({
                        error: `La clase de ${clase.days.join(', ')} ${clase.start} está llena`
                    });
                }
            }
        }

        // Crear alumno
        const student = {
            dni,
            name,
            lastName,
            phone,
            emergencyContact,
            membershipType,
            dueDate: dueDate ? new Date(dueDate) : null,
            role: 'alumno',
            // Assign the student's gym to the creator's gym when available
            gymId: (req.user && req.user.gymId) ? req.user.gymId : null,
            createdAt: new Date()
        };

        const result = await db.collection('users').insertOne(student);
        const studentId = result.insertedId;

        // Inscribir en las clases especificadas
        if (classIds.length > 0) {
            await db.collection('classes').updateMany(
                { _id: { $in: classIds.map(id => new ObjectId(id)) } },
                { $push: { students: studentId } }
            );
        }

        // Also add the student to future generated instances of those classes
        if (classIds.length > 0) {
            const now = new Date();
            await db.collection('classInstances').updateMany(
                { classId: { $in: classIds.map(id => new ObjectId(id)) }, dateTime: { $gte: now }, status: 'scheduled' },
                { $push: { students: studentId }, $set: { updatedAt: new Date() } }
            );
        }

        res.json({ id: studentId });
        try { sendSseEvent('classes', { action: 'studentCreated', studentId: studentId, classIds }, req.user && req.user.gymId ? req.user.gymId : null); } catch (e) { }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al crear alumno' });
    }
});

// Endpoint para recibir solicitudes de registro desde el formulario público
// Guarda la solicitud en `registerRequests` y, si el usuario pidió suscripción,
// crea una entrada en `subscriptions` con estado 'pending' para ser procesada
// cuando se configuren las credenciales de Mercado Pago.
app.post('/api/register-request', async (req, res) => {
    try {
        const { gymName, phone, email, password, wantsSubscription } = req.body || {};
        if (!gymName || !email || !password) {
            return res.status(400).json({ error: 'gymName, email y password son requeridos' });
        }

        const hashed = await bcrypt.hash(String(password), 10);
        const requestDoc = {
            gymName,
            phone: phone || null,
            email: String(email).toLowerCase(),
            hashedPassword: hashed,
            wantsSubscription: !!wantsSubscription,
            status: 'pending',
            createdAt: new Date()
        };

        const result = await db.collection('registerRequests').insertOne(requestDoc);

        // If subscription requested, create a subscription record for later processing
        if (wantsSubscription) {
            const defaultAmount = Number(process.env.SUBSCRIPTION_AMOUNT || 2000);
            const defaultCurrency = process.env.SUBSCRIPTION_CURRENCY || 'ARS';
            const subDoc = {
                requestId: result.insertedId,
                email: String(email).toLowerCase(),
                gymName,
                phone: phone || null,
                hashedPassword: hashed,
                plan: {
                    name: process.env.SUBSCRIPTION_PLAN_NAME || 'Membresía mensual',
                    amount: defaultAmount,
                    currency: defaultCurrency,
                    interval: 'months',
                    intervalCount: 1
                },
                status: 'pending', // pending until webhook confirms
                createdAt: new Date()
            };
            await db.collection('subscriptions').insertOne(subDoc);
        }

        res.status(201).json({ ok: true, id: result.insertedId });
    } catch (err) {
        console.error('Error en /api/register-request:', err);
        res.status(500).json({ error: 'Error al procesar la solicitud' });
    }
});

// Register request via Google Sign-In (id_token)
app.post('/api/register-request/google', async (req, res) => {
    try {
        const { idToken, gymName, phone, wantsSubscription } = req.body || {};
        if (!idToken || !gymName) return res.status(400).json({ error: 'idToken y gymName son requeridos' });

        // Verify token with Google's tokeninfo endpoint (same logic used in /api/auth/google)
        const tokenInfoUrl = 'https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(idToken);
        let info = null;
        if (typeof fetch === 'function') {
            const r = await fetch(tokenInfoUrl);
            if (!r.ok) return res.status(401).json({ error: 'Token inválido' });
            info = await r.json();
        } else {
            info = await new Promise((resolve, reject) => {
                const https = require('https');
                https.get(tokenInfoUrl, (r) => {
                    let data = '';
                    r.on('data', chunk => data += chunk);
                    r.on('end', () => {
                        try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
                    });
                }).on('error', reject);
            });
        }

        const email = info && (info.email || (info.email_verified && info.email)) ? info.email : null;
        const emailVerified = info && (info.email_verified === 'true' || info.email_verified === true);
        if (!email || !emailVerified) return res.status(401).json({ error: 'Email no verificado por Google' });

        // Normalize email
        const normalizedEmail = String(email).toLowerCase();

        // Create register request entry (without password) to be reviewed by admin
        const requestDoc = {
            gymName,
            phone: phone || null,
            email: normalizedEmail,
            provider: 'google',
            providerId: info && info.sub ? String(info.sub) : null,
            wantsSubscription: !!wantsSubscription,
            status: 'pending',
            createdAt: new Date()
        };

        const result = await db.collection('registerRequests').insertOne(requestDoc);

        // If subscription requested, create a subscriptions record for later processing
        if (wantsSubscription) {
            const defaultAmount = Number(process.env.SUBSCRIPTION_AMOUNT || 2000);
            const defaultCurrency = process.env.SUBSCRIPTION_CURRENCY || 'ARS';
            const subDoc = {
                requestId: result.insertedId,
                email: normalizedEmail,
                gymName,
                phone: phone || null,
                plan: {
                    name: process.env.SUBSCRIPTION_PLAN_NAME || 'Membresía mensual',
                    amount: defaultAmount,
                    currency: defaultCurrency,
                    interval: 'months',
                    intervalCount: 1
                },
                status: 'pending',
                createdAt: new Date()
            };
            await db.collection('subscriptions').insertOne(subDoc);
        }

        return res.status(201).json({ ok: true, id: result.insertedId });
    } catch (err) {
        console.error('Error in /api/register-request/google:', err && err.message ? err.message : err);
        res.status(500).json({ error: 'Error procesando registro con Google' });
    }
});

app.put('/api/students/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const {
        dni, name, lastName, phone, emergencyContact,
        membershipType, dueDate, classIds = []
    } = req.body;

    if (!dni || !name || !lastName) {
        return res.status(400).json({ error: 'DNI, nombre y apellido son requeridos' });
    }

    try {
        const _id = new ObjectId(id);

        // Verificar que el alumno exista
        const currentStudent = await db.collection('users').findOne({ _id, role: 'alumno' });
        if (!currentStudent) {
            return res.status(404).json({ error: 'Alumno no encontrado' });
        }

        // Verificar DNI duplicado (excepto si es el mismo alumno)
        const exists = await db.collection('users').findOne({ dni, _id: { $ne: _id } });
        if (exists) {
            return res.status(409).json({ error: 'Ya existe otro usuario con ese DNI' });
        }

        // Obtener clases actuales del alumno
        const currentClasses = await db.collection('classes')
            .find({ students: _id })
            .toArray();

        const currentClassIds = currentClasses.map(c => c._id.toString());
        const classesToAdd = classIds.filter(id => !currentClassIds.includes(id));
        const classesToRemove = currentClassIds.filter(id => !classIds.includes(id));

        // Validar capacidad en las nuevas clases
        if (classesToAdd.length > 0) {
            const newClasses = await db.collection('classes')
                .find({ _id: { $in: classesToAdd.map(id => new ObjectId(id)) } })
                .toArray();

            for (const clase of newClasses) {
                const room = await db.collection('rooms').findOne({ _id: new ObjectId(clase.roomId) });
                if (!room) continue;

                const studentsCount = clase.students ? clase.students.length : 0;
                if (studentsCount >= room.capacity) {
                    return res.status(400).json({
                        error: `La clase de ${clase.days.join(', ')} ${clase.start} está llena`
                    });
                }
            }
        }

        // Actualizar datos del alumno
        await db.collection('users').updateOne(
            { _id },
            {
                $set: {
                    dni,
                    name,
                    lastName,
                    phone,
                    emergencyContact,
                    membershipType,
                    dueDate: dueDate ? new Date(dueDate) : null,
                    updatedAt: new Date()
                }
            }
        );

        // Si se actualizó la cuota (dueDate) queremos asegurar que las instancias
        // de clases se generen hasta el nuevo vencimiento + grace (autoCancelDueOverdueDays)
        // y que el alumno esté registrado en esas instancias para que la UI muestre
        // todas las clases hasta el vencimiento inmediatamente.
        if (dueDate) {
            try {
                // Calcular upperLimit = dueDate + gym.autoCancelDueOverdueDays
                const gym = await db.collection('gyms').findOne({}) || DEFAULT_GYM_CONFIG;
                const extraDays = (gym && gym.autoCancelDueOverdueDays) ? Number(gym.autoCancelDueOverdueDays) : DEFAULT_GYM_CONFIG.autoCancelDueOverdueDays;
                const venc = new Date(dueDate);
                const upperLimit = new Date(venc);
                upperLimit.setDate(upperLimit.getDate() + (extraDays || 0));

                // Calcular días a generar desde hoy (start of day)
                const today = new Date();
                today.setHours(0, 0, 0, 0);
                let daysAhead = Math.ceil((upperLimit - today) / 864e5);
                if (daysAhead < 0) daysAhead = 0;
                // Limitar por seguridad (no generar más de 90 días de golpe)
                const MAX_GENERATE_DAYS = 90;
                if (daysAhead > MAX_GENERATE_DAYS) daysAhead = MAX_GENERATE_DAYS;

                if (daysAhead > 0) {
                    // Generar instancias globalmente (la función ya itera por todas las clases)
                    await generateClassInstances(daysAhead);

                    // Obtener las clases en las que el alumno está inscrito ahora
                    const enrolledClasses = await db.collection('classes').find({ students: _id }).project({ _id: 1 }).toArray();
                    const enrolledClassIds = enrolledClasses.map(c => c._id);

                    if (enrolledClassIds.length > 0) {
                        // Añadir al alumno a las instancias futuras (hasta upperLimit) de sus clases
                        await db.collection('classInstances').updateMany(
                            {
                                classId: { $in: enrolledClassIds },
                                dateTime: { $gte: new Date(), $lte: upperLimit },
                                status: 'scheduled'
                            },
                            { $addToSet: { students: _id }, $set: { updatedAt: new Date() } }
                        );
                    }
                }
            } catch (e) {
                console.warn('Warning: failed to generate/sync classInstances after dueDate update for student', id, e);
            }
        }

        // Actualizar inscripciones a clases
        if (classesToAdd.length > 0) {
            await db.collection('classes').updateMany(
                { _id: { $in: classesToAdd.map(id => new ObjectId(id)) } },
                { $push: { students: _id } }
            );
            // Also add student to future instances of added classes
            const now = new Date();
            await db.collection('classInstances').updateMany(
                { classId: { $in: classesToAdd.map(id => new ObjectId(id)) }, dateTime: { $gte: now }, status: 'scheduled' },
                { $push: { students: _id }, $set: { updatedAt: new Date() } }
            );
        }

        if (classesToRemove.length > 0) {
            await db.collection('classes').updateMany(
                { _id: { $in: classesToRemove.map(id => new ObjectId(id)) } },
                { $pull: { students: _id } }
            );
            // Also remove student from future instances of removed classes
            const now2 = new Date();
            await db.collection('classInstances').updateMany(
                { classId: { $in: classesToRemove.map(id => new ObjectId(id)) }, dateTime: { $gte: now2 }, status: 'scheduled' },
                { $pull: { students: _id }, $set: { updatedAt: new Date() } }
            );
        }

        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al actualizar alumno' });
    }
});

app.delete('/api/students/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        const _id = new ObjectId(id);

        // Verificar que el alumno exista
        const student = await db.collection('users').findOne({ _id, role: 'alumno' });
        if (!student) {
            return res.status(404).json({ error: 'Alumno no encontrado' });
        }

        // Verificar que el alumno pertenezca al mismo gym que el admin (salvo superusuario)
        if (req.user.role !== 'superusuario' && student.gymId && student.gymId !== req.user.gymId) {
            return res.status(403).json({ error: 'No tenés permisos para eliminar este alumno' });
        }

        // Eliminar alumno de todas las clases
        await db.collection('classes').updateMany(
            { students: _id },
            { $pull: { students: _id } }
        );

        // Eliminar alumno
        await db.collection('users').deleteOne({ _id });

        try { sendSseEvent('students', { action: 'deleted', studentId: id }, req.user && req.user.gymId ? req.user.gymId : null); } catch (e) { }
        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al eliminar alumno' });
    }
});

app.post('/api/rooms', authMiddleware, async (req, res) => {
    const { name, capacity } = req.body;
    if (!name || !capacity) return res.status(400).json({ error: 'Nombre y capacidad son requeridos' });
    try {
        // rooms are per-gym
        const q = { name, gymId: req.user.gymId };
        const exists = await db.collection('rooms').findOne(q);
        if (exists) return res.status(409).json({ error: 'Ya existe un salón con ese nombre en este gimnasio' });
        const result = await db.collection('rooms').insertOne({ name, capacity: Number(capacity), gymId: req.user.gymId });
        res.json({ id: result.insertedId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al crear salón' });
    }
});

app.put('/api/rooms/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const { name, capacity } = req.body;
    if (!name || !capacity) return res.status(400).json({ error: 'Nombre y capacidad son requeridos' });
    try {
        const { ObjectId } = require('mongodb');
        const _id = new ObjectId(id);
        // Ensure room belongs to gym (unless superusuario)
        const room = await db.collection('rooms').findOne({ _id });
        if (!room) return res.status(404).json({ error: 'Salón no encontrado' });
        if (req.user.role !== 'superusuario') {
            if (room.gymId && req.user.gymId && String(room.gymId) !== String(req.user.gymId)) return res.status(403).json({ error: 'No tenés permisos para modificar este salón' });
            if (!req.user.gymId) console.warn('[PERM] user has no gymId on profile while modifying room', { userId: req.user && req.user.id, roomId: _id });
        }
        await db.collection('rooms').updateOne({ _id }, { $set: { name, capacity: Number(capacity) } });
        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al actualizar salón' });
    }
});

app.delete('/api/rooms/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        const { ObjectId } = require('mongodb');
        const _id = new ObjectId(id);
        const room = await db.collection('rooms').findOne({ _id });
        if (!room) return res.status(404).json({ error: 'Salón no encontrado' });
        if (req.user.role !== 'superusuario') {
            if (room.gymId && req.user.gymId && String(room.gymId) !== String(req.user.gymId)) return res.status(403).json({ error: 'No tenés permisos para eliminar este salón' });
            if (!req.user.gymId) console.warn('[PERM] user has no gymId on profile while deleting room', { userId: req.user && req.user.id, roomId: _id });
        }
        await db.collection('rooms').deleteOne({ _id });
        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al eliminar salón' });
    }
});

// CRUD Clases (classes)

// Validaciones
function validateTime(time) {
    return /^([0-1][0-9]|2[0-3]):[0-5][0-9]$/.test(time);
}

function validateDuration(duration) {
    return Number.isInteger(duration) && duration > 0 && duration <= 180;
}

// Calcula camillas libres y valida capacidad
async function validateClassCapacity(roomId, classId = null) {
    const room = await db.collection('rooms').findOne({ _id: new ObjectId(roomId) });
    if (!room) throw new Error('Salón no encontrado');
    return { capacity: room.capacity, name: room.name };
}

app.get('/api/classes', authMiddleware, async (req, res) => {
    try {
        const q = {};
        if (req.user.role !== 'superusuario') q.gymId = req.user.gymId;
        const classes = await db.collection('classes').find(q).toArray();
        // populate room and professor and calculate camillas libres
        const populated = await Promise.all(classes.map(async c => {
            const room = c.roomId ? await db.collection('rooms').findOne({ _id: new ObjectId(c.roomId) }) : null;
            const professor = c.professorId ? await db.collection('users').findOne({ _id: new ObjectId(c.professorId) }) : null;
            const studentsCount = Array.isArray(c.students) ? c.students.length : 0;
            const capacity = room ? room.capacity : 0;
            return Object.assign({}, c, { roomName: room ? room.name : null, professorName: professor ? professor.name : null, camillasFree: Math.max(0, capacity - studentsCount) });
        }));
        res.json(populated);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al listar clases' });
    }
});

// Server-Sent Events endpoint for real-time updates
app.get('/api/events', async (req, res) => {
    // Allow token via query param for EventSource (browsers don't allow custom headers)
    const token = req.query && req.query.token ? req.query.token : null;
    let payload = null;
    try {
        if (!token) return res.status(401).end('token required');
        payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).end('invalid token');
    }

    // set headers for SSE
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders && res.flushHeaders();

    const client = { id: new ObjectId().toString(), res, gymId: payload.gymId || null };
    sseClients.add(client);

    // send an initial ping so the client knows connection is live
    try { res.write(`data: ${JSON.stringify({ type: 'connected', payload: { gymId: client.gymId } })}\n\n`); } catch (e) { }

    req.on('close', () => {
        sseClients.delete(client);
    });
});

app.post('/api/classes', authMiddleware, async (req, res) => {
    const { days, start, duration, roomId, professorId } = req.body;
    // Only days and start (and room) are required now; duration is optional
    // Debug: log incoming payload shape to help diagnose client/server mismatches
    try {
        console.log('[DEBUG] POST /api/classes - incoming body keys:', Object.keys(req.body || {}));
        console.log('[DEBUG] POST /api/classes - raw days:', days);
        console.log('[DEBUG] POST /api/classes - days type/len:', typeof days, Array.isArray(days), (Array.isArray(days) ? days.length : null));
        console.log('[DEBUG] POST /api/classes - start:', start, 'roomId:', roomId, 'professorId:', professorId);
    } catch (e) { console.warn('[DEBUG] POST /api/classes - failed to log incoming body', e); }

    // Normalize days: accept array, comma-separated string, or object with numeric keys
    let normDays = days;
    if (normDays && !Array.isArray(normDays)) {
        if (typeof normDays === 'string') {
            // comma separated or single value
            normDays = normDays.split(',').map(s => s.trim()).filter(Boolean);
        } else if (typeof normDays === 'object') {
            try {
                normDays = Object.values(normDays).filter(v => typeof v === 'string' && v.trim().length > 0).map(s => s.trim());
            } catch (e) { normDays = null; }
        } else {
            normDays = null;
        }
    }

    // Trim start if present
    const normStart = typeof start === 'string' ? start.trim() : start;

    // Validate required fields and return descriptive errors (room is optional)
    const missingFields = [];
    if (!normDays || !Array.isArray(normDays) || normDays.length === 0) missingFields.push('días');
    if (!normStart) missingFields.push('horario');
    if (missingFields.length) {
        const msg = 'Faltan datos requeridos: ' + missingFields.join(', ');
        console.warn('[VALIDATION] POST /api/classes - ' + msg, { body: req.body });
        return res.status(400).json({ error: msg });
    }

    // Assign normalized values back for downstream logic
    req.body.days = normDays;
    req.body.start = normStart;

    // Validar formato de hora. duration is optional and validated only when provided
    if (!validateTime(normStart))
        return res.status(400).json({ error: 'Formato de hora inválido. Use HH:MM (24h)' });
    if (duration !== undefined && duration !== null && duration !== '') {
        if (!validateDuration(Number(duration)))
            return res.status(400).json({ error: 'Duración inválida. Debe estar entre 1 y 180 minutos' });
    }

    try {
        // If a roomId was provided, validate capacity and existence; room is optional
        let room = null;
        let roomDoc = null;
        if (roomId) {
            room = await validateClassCapacity(roomId);
            if (!room) return res.status(404).json({ error: 'Salón no encontrado' });

            // Verificar que el salón pertenece al mismo gym que el admin
            roomDoc = await db.collection('rooms').findOne({ _id: new ObjectId(roomId) });
        }

        // Defensive enrichment: if authMiddleware didn't attach gymId for any reason,
        // try to load it here so permission checks are reliable.
        if (req.user && !req.user.gymId && req.user.id) {
            try {
                const u = await db.collection('users').findOne({ _id: new ObjectId(req.user.id) });
                if (u && u.gymId) {
                    req.user.gymId = u.gymId;
                    console.log('[ENRICH] POST /api/classes - attached gymId from users collection to req.user:', req.user.gymId);
                } else {
                    console.log('[ENRICH] POST /api/classes - no gymId found on user doc for', req.user.id);
                }
            } catch (e) {
                console.warn('[ENRICH] POST /api/classes - failed to enrich req.user with gymId', e && e.message ? e.message : e);
            }
        }

        if (req.user.role !== 'superusuario' && roomDoc) {
            if (roomDoc.gymId && req.user.gymId && String(roomDoc.gymId) !== String(req.user.gymId)) {
                return res.status(403).json({ error: 'No tenés permisos para usar ese salón' });
            }
            if (!req.user.gymId) {
                console.warn('[PERM] user has no gymId on profile while creating class - allowing operation but consider fixing user.gymId', { userId: req.user.id });
            }
        }

        // Validar duplicados: mismo room, mismo start y días intersectan
        // Check for conflicts in the same room only when a room was provided
        if (roomId) {
            const conflict = await db.collection('classes').findOne({
                roomId: roomId,
                start: normStart,
                days: { $in: normDays },
                gymId: req.user.gymId
            });
            if (conflict)
                return res.status(409).json({ error: 'Ya existe una clase en ese salón con el mismo horario y días' });
        }

        // Validar que el profesor exista si se proporciona
        if (professorId) {
            const professor = await db.collection('users').findOne({
                _id: new ObjectId(professorId),
                role: 'profesor'
            });
            if (!professor)
                return res.status(404).json({ error: 'Profesor no encontrado' });
        }

        const doc = {
            days: normDays,
            start: normStart,
            duration: (duration !== undefined && duration !== null && duration !== '') ? Number(duration) : null,
            roomId: roomId || null,
            professorId: professorId || null,
            gymId: req.user.gymId,
            students: [],
            createdAt: new Date()
        };

        const result = await db.collection('classes').insertOne(doc);
        // Broadcast classes change to connected clients in this gym
        try { sendSseEvent('classes', { action: 'created', id: result.insertedId }, req.user && req.user.gymId ? req.user.gymId : null); } catch (e) { }
        res.json({ id: result.insertedId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al crear clase' });
    }
});

app.put('/api/classes/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const { days, start, duration, roomId, professorId } = req.body;

    // Debug: log incoming payload for PUT
    try {
        console.log('[DEBUG] PUT /api/classes/%s - incoming body keys: %o', id, Object.keys(req.body || {}));
        console.log('[DEBUG] PUT /api/classes/%s - raw days: %o', id, days);
        console.log('[DEBUG] PUT /api/classes/%s - start: %s roomId: %s professorId: %s', id, start, roomId, professorId);
    } catch (e) { console.warn('[DEBUG] PUT /api/classes - failed to log incoming body', e); }

    // Normalize days similar to POST: accept array, comma-separated string, or object
    let normDays = days;
    if (normDays && !Array.isArray(normDays)) {
        if (typeof normDays === 'string') {
            normDays = normDays.split(',').map(s => s.trim()).filter(Boolean);
        } else if (typeof normDays === 'object') {
            try {
                normDays = Object.values(normDays).filter(v => typeof v === 'string' && v.trim().length > 0).map(s => s.trim());
            } catch (e) { normDays = null; }
        } else {
            normDays = null;
        }
    }

    const normStart = typeof start === 'string' ? start.trim() : start;

    // Validate required fields: only days and start are mandatory; room is optional
    const missing = [];
    if (!normDays || !Array.isArray(normDays) || normDays.length === 0) missing.push('días');
    if (!normStart) missing.push('horario');
    if (missing.length) {
        const msg = 'Faltan datos requeridos: ' + missing.join(', ');
        console.warn('[VALIDATION] PUT /api/classes - ' + msg, { body: req.body });
        return res.status(400).json({ error: msg });
    }

    // Validar formato de hora. duration is optional and validated only when provided
    if (!validateTime(normStart))
        return res.status(400).json({ error: 'Formato de hora inválido. Use HH:MM (24h)' });
    if (duration !== undefined && duration !== null && duration !== '') {
        if (!validateDuration(Number(duration)))
            return res.status(400).json({ error: 'Duración inválida. Debe estar entre 1 y 180 minutos' });
    }

    try {
        const _id = new ObjectId(id);

        // Validar que la clase exista
        const existingClass = await db.collection('classes').findOne({ _id });

        // Defensive enrichment: if authMiddleware didn't attach gymId for any reason
        // (older tokens or race), try to load it here from the users collection so
        // permission checks below are reliable.
        if (req.user && !req.user.gymId && req.user.id) {
            try {
                const userDoc = await db.collection('users').findOne({ _id: new ObjectId(req.user.id) });
                if (userDoc && userDoc.gymId) {
                    req.user.gymId = userDoc.gymId;
                    console.log('[ENRICH] PUT /api/classes/:id - attached gymId from users collection to req.user:', req.user.gymId);
                } else {
                    console.log('[ENRICH] PUT /api/classes/:id - no gymId found on user doc for', req.user.id);
                }
            } catch (e) {
                console.warn('[ENRICH] PUT /api/classes/:id - failed to enrich req.user with gymId', e && e.message ? e.message : e);
            }
        }
        if (!existingClass)
            return res.status(404).json({ error: 'Clase no encontrada' });

        // Determine whether the client actually provided a roomId (non-empty string).
        // Treat empty string / null / undefined as "not provided" so editing without
        // touching the room field doesn't trigger room lookups or errors.
        const providedRoom = req.body.hasOwnProperty('roomId') && roomId !== undefined && roomId !== null && String(roomId).trim() !== '';
        // Determine which room to validate: prefer provided roomId (when non-empty),
        // otherwise fall back to existing class room for display only — but DO NOT
        // perform validation/lookups when the client didn't provide a roomId.
        const effectiveRoomId = providedRoom ? roomId : (existingClass.roomId || null);

        let room = null;
        let roomDoc = null;
        if (providedRoom) {
            try {
                room = await validateClassCapacity(effectiveRoomId);
            } catch (e) {
                return res.status(404).json({ error: 'Salón no encontrado' });
            }
            roomDoc = await db.collection('rooms').findOne({ _id: new ObjectId(effectiveRoomId) });
        }

        // Permission checks: ensure requester can modify this class (same gym unless superusuario)
        try {
            console.log('[DEBUG] PUT /api/classes/:id - user payload:', req.user);
            console.log('[DEBUG] PUT /api/classes/:id - existingClass.gymId:', existingClass.gymId, ' roomDoc.gymId:', roomDoc ? roomDoc.gymId : null, ' req.user.gymId:', req.user.gymId);
        } catch (e) { /* ignore logging errors */ }

        if (req.user.role !== 'superusuario') {
            if (existingClass.gymId && req.user.gymId && String(existingClass.gymId) !== String(req.user.gymId)) {
                console.warn('[PERM] deny modify class - existingClass.gymId mismatch', { existingClassGymId: existingClass.gymId, userGymId: req.user.gymId });
                return res.status(403).json({ error: 'No tenés permisos para modificar esta clase' });
            }
            if (!req.user.gymId) console.warn('[PERM] user has no gymId on profile - allowing operation but consider fixing user.gymId', { userId: req.user.id });
        }

        // If there's a room involved, ensure it belongs to the same gym as the admin (unless superusuario)
        if (req.user.role !== 'superusuario' && roomDoc) {
            if (roomDoc.gymId && req.user.gymId && String(roomDoc.gymId) !== String(req.user.gymId)) {
                console.warn('[PERM] deny use room - roomDoc.gymId mismatch', { roomGymId: roomDoc.gymId, userGymId: req.user.gymId });
                return res.status(403).json({ error: 'No tenés permisos para usar ese salón' });
            }
            if (!req.user.gymId) console.warn('[PERM] user has no gymId on profile while using room', { userId: req.user.id, roomId: roomDoc._id });
        }

        // If there are students enrolled, validate capacity only when the client
        // provided a new room (we validated it above). Do not error when the client
        // didn't touch the room field and the existing room record is missing.
        if (providedRoom && room && existingClass.students && existingClass.students.length > room.capacity) {
            return res.status(400).json({
                error: `No se puede cambiar al salón ${room.name} porque tiene ${existingClass.students.length} estudiantes y solo tiene capacidad para ${room.capacity}`
            });
        }

        // Verificar conflicto con otras clases (excluyendo esta) cuando hay un salón efectivo
        if (providedRoom && effectiveRoomId) {
            const conflict = await db.collection('classes').findOne({
                _id: { $ne: _id },
                roomId: effectiveRoomId,
                start: normStart,
                days: { $in: normDays },
                gymId: existingClass.gymId
            });
            if (conflict) return res.status(409).json({ error: 'Conflicto con otra clase en ese salón' });
        }

        // Validar que el profesor exista si se proporciona
        if (professorId) {
            const professor = await db.collection('users').findOne({
                _id: new ObjectId(professorId),
                role: 'profesor'
            });
            if (!professor)
                return res.status(404).json({ error: 'Profesor no encontrado' });
        }

        const updateFields = {
            days: normDays,
            start: normStart,
            professorId: professorId || null,
            updatedAt: new Date()
        };
        // Only override roomId if the caller provided a non-empty value in the payload;
        // if the field was omitted or provided as an empty string, do not change it.
        if (providedRoom) updateFields.roomId = roomId || null;
        if (duration !== undefined && duration !== null && duration !== '') updateFields.duration = Number(duration);

        await db.collection('classes').updateOne(
            { _id },
            { $set: updateFields }
        );
        try { sendSseEvent('classes', { action: 'updated', id: id }, req.user && req.user.gymId ? req.user.gymId : null); } catch (e) { }
        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al actualizar clase' });
    }
});

// Focused endpoint to assign/unassign a professor to a class.
// This avoids triggering full class validation when only changing professorId.
app.post('/api/classes/:id/assign-professor', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const { professorId } = req.body || {};
    try {
        const _id = new ObjectId(id);
        const cls = await db.collection('classes').findOne({ _id });
        if (!cls) return res.status(404).json({ error: 'Clase no encontrada' });

        // Permission: ensure admin belongs to same gym as class (unless superusuario)
        if (req.user.role !== 'superusuario') {
            if (cls.gymId && req.user.gymId && String(cls.gymId) !== String(req.user.gymId)) {
                return res.status(403).json({ error: 'No tenés permisos para modificar esta clase' });
            }
            if (!req.user.gymId) console.warn('[PERM] user has no gymId on profile while assigning/unassigning professor to class', { userId: req.user && req.user.id, classId: _id });
        }

        // If assigning, ensure professor exists and belongs to same gym
        if (professorId) {
            const prof = await db.collection('users').findOne({ _id: new ObjectId(professorId), role: 'profesor' });
            if (!prof) return res.status(404).json({ error: 'Profesor no encontrado' });
            if (req.user.role !== 'superusuario' && prof.gymId && prof.gymId !== req.user.gymId) {
                return res.status(403).json({ error: 'No tenés permisos para asignar ese profesor' });
            }
        }

        await db.collection('classes').updateOne({ _id }, { $set: { professorId: professorId || null, updatedAt: new Date() } });
        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error asignando profesor a la clase' });
    }
});

app.delete('/api/classes/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        const _id = new ObjectId(id);
        const cls = await db.collection('classes').findOne({ _id });
        if (!cls) return res.status(404).json({ error: 'Clase no encontrada' });
        if (req.user.role !== 'superusuario') {
            if (cls.gymId && req.user.gymId && String(cls.gymId) !== String(req.user.gymId)) return res.status(403).json({ error: 'No tenés permisos para eliminar esta clase' });
            if (!req.user.gymId) console.warn('[PERM] user has no gymId on profile while deleting class', { userId: req.user && req.user.id, classId: _id });
        }
        await db.collection('classes').deleteOne({ _id });
        try { sendSseEvent('classes', { action: 'deleted', id: id }, req.user && req.user.gymId ? req.user.gymId : null); } catch (e) { }
        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al eliminar clase' });
    }
});

// Endpoints para gestión de estudiantes en clases

// Inscribir estudiante a una clase
app.post('/api/classes/:id/students', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const { studentId } = req.body;

    if (!studentId)
        return res.status(400).json({ error: 'ID del estudiante es requerido' });

    try {
        const _id = new ObjectId(id);
        const studentObjectId = new ObjectId(studentId);

        // Validar que la clase exista
        const classDoc = await db.collection('classes').findOne({ _id });
        if (!classDoc)
            return res.status(404).json({ error: 'Clase no encontrada' });

        // Validar que el estudiante exista y sea un estudiante
        const student = await db.collection('users').findOne({
            _id: studentObjectId,
            role: 'alumno'
        });
        if (!student)
            return res.status(404).json({ error: 'Estudiante no encontrado' });

        // Validar que el estudiante no esté ya inscrito
        if (classDoc.students && classDoc.students.some(id => id.toString() === studentId)) {
            return res.status(409).json({ error: 'El estudiante ya está inscrito en esta clase' });
        }

        // Validar capacidad del salón
        const room = await validateClassCapacity(classDoc.roomId);
        const currentStudents = classDoc.students ? classDoc.students.length : 0;
        if (currentStudents >= room.capacity) {
            return res.status(400).json({ error: 'La clase está llena' });
        }

        // Inscribir al estudiante
        await db.collection('classes').updateOne(
            { _id },
            {
                $push: { students: studentObjectId },
                $set: { updatedAt: new Date() }
            }
        );

        // Also add the student to future scheduled instances of this class
        try {
            const now = new Date();
            await db.collection('classInstances').updateMany(
                { classId: _id, dateTime: { $gte: now }, status: 'scheduled' },
                { $addToSet: { students: studentObjectId }, $set: { updatedAt: new Date() } }
            );
        } catch (e) {
            console.warn('Warning: failed to sync student into classInstances', e);
        }

        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al inscribir estudiante' });
    }
});

// CRUD Profesores
app.post('/api/professors', authMiddleware, async (req, res) => {
    const { dni, name, lastName, phone } = req.body;

    if (!dni || !name || !lastName) {
        return res.status(400).json({ error: 'DNI, nombre y apellido son requeridos' });
    }

    try {
        // Verificar DNI duplicado
        const exists = await db.collection('users').findOne({ dni });
        if (exists) {
            return res.status(409).json({ error: 'Ya existe un usuario con ese DNI' });
        }

        const professor = {
            dni,
            name,
            lastName,
            phone,
            role: 'profesor',
            gymId: req.user.gymId || null,
            createdAt: new Date()
        };

        const result = await db.collection('users').insertOne(professor);
        res.json({ id: result.insertedId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al crear profesor' });
    }
});

// Actualizar profesor
app.put('/api/professors/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const { dni, name, lastName, phone } = req.body;

    if (!dni || !name || !lastName) {
        return res.status(400).json({ error: 'DNI, nombre y apellido son requeridos' });
    }

    try {
        const _id = new ObjectId(id);

        // Verificar que el profesor exista
        const professor = await db.collection('users').findOne({ _id, role: 'profesor' });
        if (!professor) return res.status(404).json({ error: 'Profesor no encontrado' });

        // Verificar que el profesor pertenece al mismo gym (salvo superusuario)
        if (req.user.role !== 'superusuario') {
            if (professor.gymId && req.user.gymId && String(professor.gymId) !== String(req.user.gymId)) {
                return res.status(403).json({ error: 'No tenés permisos para modificar este profesor' });
            }
            if (!req.user.gymId) console.warn('[PERM] user has no gymId on profile while updating professor', { userId: req.user && req.user.id, professorId: _id });
        }

        // Verificar DNI duplicado (excepto si es el mismo profesor)
        const exists = await db.collection('users').findOne({ dni, _id: { $ne: _id } });
        if (exists) return res.status(409).json({ error: 'Ya existe otro usuario con ese DNI' });

        await db.collection('users').updateOne({ _id }, { $set: { dni, name, lastName, phone, updatedAt: new Date() } });

        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al actualizar profesor' });
    }
});

// Generar instancias de clases (llamar periódicamente o bajo demanda)
async function generateClassInstances(daysAhead = 30) {
    try {
        // Generate instances for all classes (including legacy ones without gymId)
        const classes = await db.collection('classes').find({}).toArray();
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        // Use unaccented day names to avoid mismatches (some parts of the UI use "miercoles" without accent)
        const daysNames = ['domingo', 'lunes', 'martes', 'miercoles', 'jueves', 'viernes', 'sabado'];

        // helper to strip accents and normalize
        const strip = (s = '') => s.toString().normalize('NFD').replace(/\p{Diacritic}/gu, '').toLowerCase();

        for (const clase of classes) {
            for (let dayOffset = 0; dayOffset < daysAhead; dayOffset++) {
                const targetDate = new Date(today);
                targetDate.setDate(today.getDate() + dayOffset);
                const dayName = daysNames[targetDate.getDay()];

                // Normalize clase.days entries and compare without accents
                const claseDaysNormalized = Array.isArray(clase.days) ? clase.days.map(d => strip(d)) : [];
                if (!claseDaysNormalized.includes(strip(dayName))) continue;

                // Parsear hora de inicio
                const [hours, minutes] = clase.start.split(':').map(Number);
                const instanceDateTime = new Date(targetDate);
                instanceDateTime.setHours(hours, minutes, 0, 0);

                // Verificar si ya existe esta instancia
                const exists = await db.collection('classInstances').findOne({
                    classId: clase._id,
                    dateTime: instanceDateTime
                });

                if (!exists) {
                    // Initialize instance students with currently enrolled students in the class
                    const initialStudents = Array.isArray(clase.students) ? clase.students : [];
                    await db.collection('classInstances').insertOne({
                        classId: clase._id,
                        dateTime: instanceDateTime,
                        duration: clase.duration,
                        roomId: clase.roomId,
                        professorId: clase.professorId,
                        students: initialStudents,
                        status: 'scheduled',
                        createdAt: new Date(),
                        gymId: clase.gymId || null
                    });
                }
            }
        }
    } catch (err) {
        console.error('Error generando instancias:', err);
    }
}

// Configuración del gimnasio
app.get('/api/gym/config', authMiddleware, async (req, res) => {
    try {
        // If superusuario may request specific gymId via query
        let gymId = req.user.gymId;
        if (req.user.role === 'superusuario' && req.query.gymId) gymId = req.query.gymId;
        const config = gymId ? await db.collection('gyms').findOne({ gymId }) : await db.collection('gyms').findOne({});
        res.json(config || DEFAULT_GYM_CONFIG);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al obtener configuración' });
    }
});

// Endpoint seguro para que cualquier usuario autenticado obtenga la config de su gym
app.get('/api/gym/config/me', authAny, async (req, res) => {
    try {
        const gymId = req.user && req.user.gymId ? req.user.gymId : null;
        const config = gymId ? await db.collection('gyms').findOne({ gymId }) : await db.collection('gyms').findOne({});
        res.json(config || DEFAULT_GYM_CONFIG);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al obtener configuración del gimnasio' });
    }
});

app.put('/api/gym/config', authMiddleware, async (req, res) => {
    const {
        minCancellationHours,
        creditExpirationDays,
        autoCancelDueOverdueDays,
        maxCredits
    } = req.body;

    // Validar que los campos sean enteros y respeten límites aceptables.
    // minCancellationHours and creditExpirationDays must be > 0.
    // autoCancelDueOverdueDays and maxCredits may be >= 0.
    if (!Number.isInteger(minCancellationHours) || minCancellationHours <= 0) {
        return res.status(400).json({ error: 'minCancellationHours debe ser un número entero positivo' });
    }
    if (!Number.isInteger(creditExpirationDays) || creditExpirationDays <= 0) {
        return res.status(400).json({ error: 'creditExpirationDays debe ser un número entero positivo' });
    }
    if (!Number.isInteger(autoCancelDueOverdueDays) || autoCancelDueOverdueDays < 0) {
        return res.status(400).json({ error: 'autoCancelDueOverdueDays debe ser un número entero mayor o igual a 0' });
    }
    if (!Number.isInteger(maxCredits) || maxCredits < 0) {
        return res.status(400).json({ error: 'maxCredits debe ser un número entero mayor o igual a 0' });
    }

    try {
        // Build the fields object to persist (include membershipTypes if provided)
        const fields = {
            minCancellationHours,
            creditExpirationDays,
            autoCancelDueOverdueDays,
            maxCredits
        };

        // Optional membershipTypes: must be an array of non-empty strings when provided
        if (req.body.membershipTypes !== undefined) {
            if (!Array.isArray(req.body.membershipTypes) || !req.body.membershipTypes.every(t => typeof t === 'string' && t.trim().length > 0)) {
                return res.status(400).json({ error: 'membershipTypes debe ser un array de strings no vacíos' });
            }
            fields.membershipTypes = req.body.membershipTypes.map(t => t.trim());
        }

        // Update the gym config for the admin's gym (or specified gym if superusuario)
        let gymId = req.user.gymId;
        if (req.user.role === 'superusuario' && req.query.gymId) gymId = req.query.gymId;
        if (gymId) {
            const gym = await db.collection('gyms').findOne({ gymId });
            if (gym) {
                await db.collection('gyms').updateOne(
                    { _id: gym._id },
                    { $set: { ...fields, updatedAt: new Date() } }
                );
            } else {
                await db.collection('gyms').insertOne({ gymId, ...fields, createdAt: new Date() });
            }
        } else {
            // fallback to single global gym doc
            const gym = await db.collection('gyms').findOne({});
            if (gym) {
                await db.collection('gyms').updateOne(
                    { _id: gym._id },
                    { $set: { ...fields, updatedAt: new Date() } }
                );
            } else {
                await db.collection('gyms').insertOne({ ...fields, createdAt: new Date() });
            }
        }

        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al actualizar configuración' });
    }
});

app.delete('/api/professors/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        const _id = new ObjectId(id);

        // Verificar que el profesor exista
        const professor = await db.collection('users').findOne({ _id, role: 'profesor' });
        if (!professor) {
            return res.status(404).json({ error: 'Profesor no encontrado' });
        }

        // Verificar si está asignado a clases (solo en su gym)
        const classQuery = { professorId: _id };
        if (req.user.role !== 'superusuario') classQuery.gymId = req.user.gymId;
        const assignedClasses = await db.collection('classes')
            .find(classQuery)
            .toArray();

        if (assignedClasses.length > 0) {
            return res.status(400).json({
                error: 'No se puede eliminar el profesor porque está asignado a una o más clases'
            });
        }

        // Verificar que el profesor pertenece al mismo gym (salvo superusuario)
        if (req.user.role !== 'superusuario' && professor.gymId && professor.gymId !== req.user.gymId) {
            return res.status(403).json({ error: 'No tenés permisos para eliminar este profesor' });
        }

        // Eliminar profesor
        await db.collection('users').deleteOne({ _id });

        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al eliminar profesor' });
    }
});

// Dar de baja estudiante de una clase
app.delete('/api/classes/:id/students/:studentId', authMiddleware, async (req, res) => {
    const { id, studentId } = req.params;

    try {
        const _id = new ObjectId(id);
        const studentObjectId = new ObjectId(studentId);

        // Validar que la clase exista
        const classDoc = await db.collection('classes').findOne({ _id });
        if (!classDoc)
            return res.status(404).json({ error: 'Clase no encontrada' });

        // Verificar que la clase pertenece al mismo gym que el admin
        if (req.user.role !== 'superusuario') {
            if (classDoc.gymId && req.user.gymId && String(classDoc.gymId) !== String(req.user.gymId)) {
                return res.status(403).json({ error: 'No tenés permisos para inscribir estudiantes en esta clase' });
            }
            if (!req.user.gymId) console.warn('[PERM] user has no gymId on profile while enrolling student into class', { userId: req.user && req.user.id, classId: _id });
        }

        // Validar que el estudiante esté inscrito
        if (!classDoc.students || !classDoc.students.some(id => id.toString() === studentId)) {
            return res.status(404).json({ error: 'El estudiante no está inscrito en esta clase' });
        }

        // Dar de baja al estudiante
        await db.collection('classes').updateOne(
            { _id },
            {
                $pull: { students: studentObjectId },
                $set: { updatedAt: new Date() }
            }
        );

        // Also remove the student from future scheduled instances of this class
        try {
            const now = new Date();
            await db.collection('classInstances').updateMany(
                { classId: _id, dateTime: { $gte: now }, status: 'scheduled' },
                { $pull: { students: studentObjectId }, $set: { updatedAt: new Date() } }
            );
        } catch (e) {
            console.warn('Warning: failed to remove student from classInstances', e);
        }

        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al dar de baja estudiante' });
    }
});

// Cancelar clase para un alumno (genera un ticket de crédito) - puede hacerlo el propio alumno o admin/superusuario
app.post('/api/students/:id/cancel/:classId', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }

    const { id, classId } = req.params;
    // Permitir si es admin/superusuario o es el propio alumno
    if (!['administrador', 'superusuario'].includes(payload.role) && payload.id !== id) {
        return res.status(403).json({ error: 'No tienes permisos para cancelar esta clase' });
    }

    try {
        const studentObjectId = new ObjectId(id);
        const classObjectId = new ObjectId(classId);

        const classDoc = await db.collection('classes').findOne({ _id: classObjectId });
        if (!classDoc) return res.status(404).json({ error: 'Clase no encontrada' });

        // Ensure the class belongs to the same gym as the requester (unless superusuario)
        if (payload.role !== 'superusuario' && classDoc.gymId && classDoc.gymId !== payload.gymId) {
            return res.status(403).json({ error: 'No tenés permisos para cancelar esta clase' });
        }

        // Verificar que el alumno esté inscrito
        if (!classDoc.students || !classDoc.students.some(sid => sid.toString() === id)) {
            return res.status(404).json({ error: 'El estudiante no está inscrito en esta clase' });
        }

        // Remover al estudiante de la clase
        await db.collection('classes').updateOne(
            { _id: classObjectId },
            { $pull: { students: studentObjectId }, $set: { updatedAt: new Date() } }
        );

        // Obtener configuración del gimnasio para duración de crédito
        const gym = await db.collection('gyms').findOne({}) || DEFAULT_GYM_CONFIG;
        const creditDays = gym.creditExpirationDays || DEFAULT_GYM_CONFIG.creditExpirationDays;

        // Crear ticket de crédito y persistir en el documento del alumno
        const ticket = {
            id: new ObjectId().toString(),
            classId: classId,
            classSnapshot: {
                days: classDoc.days,
                start: classDoc.start,
                duration: classDoc.duration,
                roomId: classDoc.roomId,
                professorId: classDoc.professorId
            },
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + creditDays * 24 * 60 * 60 * 1000),
            status: 'active'
        };

        await db.collection('users').updateOne(
            { _id: studentObjectId },
            { $push: { tickets: ticket }, $set: { updatedAt: new Date() } }
        );

        res.json({ ticket });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al cancelar clase y crear ticket' });
    }
});

// Recuperar una clase usando un ticket (el alumno o admin pueden ejecutar)
app.post('/api/students/:id/recover/:classId', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }

    const { id, classId } = req.params;
    const { ticketId } = req.body;
    if (!ticketId) return res.status(400).json({ error: 'ticketId es requerido' });

    // Permitir si es admin/superusuario o es el propio alumno
    if (!['administrador', 'superusuario'].includes(payload.role) && payload.id !== id) {
        return res.status(403).json({ error: 'No tienes permisos para recuperar esta clase' });
    }

    try {
        const studentObjectId = new ObjectId(id);
        const classObjectId = new ObjectId(classId);

        const user = await db.collection('users').findOne({ _id: studentObjectId });
        if (!user) return res.status(404).json({ error: 'Alumno no encontrado' });

        const ticket = (user.tickets || []).find(t => t.id === ticketId);
        if (!ticket) return res.status(404).json({ error: 'Ticket no encontrado' });
        if (ticket.status !== 'active') return res.status(400).json({ error: 'Ticket ya fue usado o no está activo' });
        if (new Date(ticket.expiresAt) < new Date()) return res.status(400).json({ error: 'Ticket expirado' });
        if (ticket.classId !== classId) return res.status(400).json({ error: 'El ticket no corresponde a esta clase' });

        const classDoc = await db.collection('classes').findOne({ _id: classObjectId });
        if (!classDoc) return res.status(404).json({ error: 'Clase no encontrada' });

        // Ensure the class belongs to the same gym as the requester (unless superusuario)
        if (payload.role !== 'superusuario' && classDoc.gymId && classDoc.gymId !== payload.gymId) {
            return res.status(403).json({ error: 'No tenés permisos para recuperar esta clase' });
        }

        // Verificar capacidad
        const room = classDoc.roomId ? await db.collection('rooms').findOne({ _id: new ObjectId(classDoc.roomId) }) : null;
        const studentsCount = Array.isArray(classDoc.students) ? classDoc.students.length : 0;
        const capacity = room ? room.capacity : 0;
        if (studentsCount >= capacity) {
            return res.status(400).json({ error: 'La clase está llena' });
        }

        // Inscribir nuevamente al alumno
        await db.collection('classes').updateOne(
            { _id: classObjectId },
            { $push: { students: studentObjectId }, $set: { updatedAt: new Date() } }
        );

        // Marcar ticket como usado
        await db.collection('users').updateOne(
            { _id: studentObjectId, 'tickets.id': ticketId },
            { $set: { 'tickets.$.status': 'used', 'tickets.$.usedAt': new Date(), updatedAt: new Date() } }
        );

        res.json({ ok: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al recuperar clase con ticket' });
    }
});

// Listar estudiantes de una clase
app.get('/api/classes/:id/students', authMiddleware, async (req, res) => {
    const { id } = req.params;

    try {
        const _id = new ObjectId(id);

        // Obtener la clase
        const classDoc = await db.collection('classes').findOne({ _id });
        if (!classDoc)
            return res.status(404).json({ error: 'Clase no encontrada' });

        // Ensure the requester can access this class (same gym or superusuario)
        if (req.user.role !== 'superusuario' && classDoc.gymId && classDoc.gymId !== req.user.gymId) {
            return res.status(403).json({ error: 'No tenés permisos para ver los estudiantes de esta clase' });
        }

        // Si no hay estudiantes, devolver array vacío
        if (!classDoc.students || classDoc.students.length === 0) {
            return res.json([]);
        }

        // Obtener detalles de los estudiantes
        const students = await db.collection('users')
            .find({
                _id: { $in: classDoc.students },
                role: 'alumno'
            })
            .project({ password: 0 }) // Excluir contraseña
            .toArray();

        res.json(students);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al listar estudiantes' });
    }
});

// Listar alumnos pertenecientes a las clases de un profesor
// - Administradores pueden listar por cualquier profesor id
// - Profesores autenticados sólo pueden listar sus propios alumnos
app.get('/api/professors/:id/students', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'No autorizado' });
    const parts = auth.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Token mal formado' });
    const token = parts[1];
    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido' });
    }

    const profId = req.params.id;

    // If caller is a profesor they can only request their own students
    if (payload.role === 'profesor' && String(payload.id) !== String(profId)) {
        return res.status(403).json({ error: 'No tenés permisos para ver los alumnos de otro profesor' });
    }

    try {
        // Find classes taught by this professor (limit by gymId if present)
        const q = {};
        if (payload.gymId) q.gymId = payload.gymId;
        // professorId in classes may be stored as string or ObjectId depending on how
        // classes were created. Accept both by querying for either form when possible.
        try {
            const oid = new ObjectId(profId);
            q.$or = [{ professorId: profId }, { professorId: oid }];
        } catch (e) {
            q.professorId = profId;
        }
        const classes = await db.collection('classes').find(q).toArray();

        const studentIdSet = new Set();
        for (const c of classes) {
            if (Array.isArray(c.students)) {
                for (const s of c.students) studentIdSet.add(String(s));
            }
        }

        if (studentIdSet.size === 0) return res.json([]);

        const ids = Array.from(studentIdSet).map(s => new ObjectId(s));

        // Optional search query
        const search = req.query.search;
        const userQ = { _id: { $in: ids }, role: 'alumno' };
        if (search) {
            const re = new RegExp(search, 'i');
            userQ.$or = [{ name: re }, { lastName: re }, { dni: re }];
        }

        const students = await db.collection('users').find(userQ).project({ password: 0 }).toArray();
        res.json(students);
    } catch (err) {
        console.error('Error listing professor students:', err);
        res.status(500).json({ error: 'Error al listar alumnos del profesor' });
    }
});

// Superusuario: crear administrador + gym
app.post('/api/superusuario/admins', authMiddleware, async (req, res) => {
    // Only superusuario may call
    if (!req.user || req.user.role !== 'superusuario') return res.status(403).json({ error: 'No tenés permisos' });
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email y password son requeridos' });
    try {
        // verificar email unico
        const exists = await db.collection('users').findOne({ email });
        if (exists) return res.status(409).json({ error: 'Ya existe un usuario con ese email' });

        // crear gym
        const newGymId = new ObjectId().toString();
        await db.collection('gyms').insertOne({ gymId: newGymId, ...DEFAULT_GYM_CONFIG, createdAt: new Date() });

        // crear administrador
        const hashed = await bcrypt.hash(password, 10);
        const admin = {
            email,
            password: hashed,
            role: 'administrador',
            gymId: newGymId,
            createdAt: new Date()
        };
        const result = await db.collection('users').insertOne(admin);
        res.json({ id: result.insertedId, gymId: newGymId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error creando administrador' });
    }
});

// Serve static files in workspace root
app.use(express.static(path.join(__dirname)));

// Handle JSON parse errors from body-parser and return JSON instead of HTML
// This prevents the client from receiving an HTML error page when it sent
// malformed JSON (which previously caused the client to try parsing '<!DOCTYPE' as JSON).
app.use((err, req, res, next) => {
    if (err && err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        console.error('Invalid JSON payload:', err && err.message ? err.message : err);
        return res.status(400).json({ error: 'Invalid JSON payload' });
    }
    next(err);
});

const PORT = process.env.PORT || 3000;

connectDB().then(async () => {
    // Generar instancias al iniciar el servidor
    await generateClassInstances(30);

    // Regenerar instancias cada 24 horas
    setInterval(() => generateClassInstances(30), 24 * 60 * 60 * 1000);

    const HOST = process.env.HOST || '0.0.0.0';
    app.listen(PORT, HOST, () => console.log(`Server listening on ${HOST}:${PORT}`));
}).catch(err => {
    console.error('Failed to connect to DB', err);
    process.exit(1);
});
