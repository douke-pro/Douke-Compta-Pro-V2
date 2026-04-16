// =============================================================================
// FICHIER : server.js
// Version : V2 — Point d'entrée principal
// Compatible : odooService.js V1 (JSON-RPC node-fetch)
// =============================================================================

const express   = require('express');
const cors      = require('cors');
const path      = require('path');
const fs        = require('fs');
const nodeFetch = require('node-fetch');
const fetch     = nodeFetch.default || nodeFetch;

require('dotenv').config();

// =============================================================================
// VÉRIFICATIONS CRITIQUES AU DÉMARRAGE
// =============================================================================

const REQUIRED_ENV = [
    'JWT_SECRET',
    'ODOO_URL',
    'ODOO_DB',
    'ODOO_USERNAME',
    'ODOO_API_KEY',
    'ODOO_ADMIN_UID',
];

const missingEnv = REQUIRED_ENV.filter(v => !process.env[v]);
if (missingEnv.length > 0) {
    console.error('❌ FATAL: Variables manquantes dans .env :');
    missingEnv.forEach(v => console.error(`   → ${v}`));
    process.exit(1);
}

// =============================================================================
// IMPORTS
// =============================================================================

// ── Services ─────────────────────────────────────────────────────────────────
const pool = require('./services/dbService');

// ── Middleware ────────────────────────────────────────────────────────────────
const { securityHeaders } = require('./middleware/auth');

// ── Routes ────────────────────────────────────────────────────────────────────
const authRoutes          = require('./routes/auth');
const companyRoutes       = require('./routes/company');
const accountingRoutes    = require('./routes/accounting');
const userRoutes          = require('./routes/user');
const settingsRoutes      = require('./routes/settings');
const adminUsersRoutes    = require('./routes/adminUsers');
const notificationsRoutes = require('./routes/notifications');
const ocrRoutes           = require('./routes/ocr');
const immobilisationsRoutes = require('./routes/immobilisations');
const reportsRoutes       = require('./routes/reports');
const messagesRoutes      = require('./routes/messages');

// =============================================================================
// INITIALISATION EXPRESS
// =============================================================================

const app  = express();
const PORT = process.env.PORT || 3000;

// =============================================================================
// CRÉATION AUTOMATIQUE DES DOSSIERS UPLOADS
// =============================================================================

const uploadDirs = [
    'uploads',
    'uploads/temp',
    'uploads/invoices',
    'uploads/documents',
    'uploads/ocr',
    'uploads/ocr/invoices',
    'uploads/ocr/bank',
];

uploadDirs.forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        console.log(`   ✅ Dossier créé: ${dir}`);
    }
});

// =============================================================================
// INITIALISATION BASE DE DONNÉES
// =============================================================================

const initDB = async (retries = 5, delay = 3000) => {
    for (let attempt = 1; attempt <= retries; attempt++) {
        try {
            console.log(`[DB] Tentative ${attempt}/${retries}...`);

            // Tables V2 (IF NOT EXISTS = idempotent)
            await pool.query(`
                CREATE TABLE IF NOT EXISTS financial_reports_requests (
                    id                  SERIAL PRIMARY KEY,
                    user_id             INTEGER NOT NULL,
                    company_id          INTEGER NOT NULL,
                    accounting_system   VARCHAR(50),
                    period_start        DATE,
                    period_end          DATE,
                    fiscal_year         VARCHAR(20),
                    requested_by        INTEGER NOT NULL,
                    requested_by_name   VARCHAR(255),
                    requested_by_email  VARCHAR(255),
                    status              VARCHAR(50) DEFAULT 'pending',
                    assigned_to         INTEGER,
                    assigned_to_name    VARCHAR(255),
                    processed_by        INTEGER,
                    validated_by        INTEGER,
                    report_types        JSONB DEFAULT '["BILAN","COMPTE_RESULTAT","BALANCE","GRAND_LIVRE"]',
                    pdf_files           JSONB,
                    odoo_data           JSONB,
                    notes               TEXT,
                    rejection_reason    TEXT,
                    error_message       TEXT,
                    requested_at        TIMESTAMP DEFAULT NOW(),
                    processed_at        TIMESTAMP,
                    validated_at        TIMESTAMP,
                    sent_at             TIMESTAMP,
                    updated_at          TIMESTAMP DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS revoked_tokens (
                    token_hash  VARCHAR(64) PRIMARY KEY,
                    revoked_at  TIMESTAMP DEFAULT NOW(),
                    expires_at  TIMESTAMP NOT NULL
                );

                CREATE TABLE IF NOT EXISTS notifications (
                    id                  SERIAL PRIMARY KEY,
                    recipient_user_id   INTEGER NOT NULL,
                    sender_user_id      INTEGER,
                    sender_name         VARCHAR(150),
                    type                VARCHAR(50) NOT NULL,
                    title               VARCHAR(255) NOT NULL,
                    message             TEXT,
                    metadata            JSONB DEFAULT '{}',
                    priority            VARCHAR(20) DEFAULT 'normal',
                    action_url          VARCHAR(500),
                    read_at             TIMESTAMP,
                    expires_at          TIMESTAMP,
                    created_at          TIMESTAMP DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS messages (
                    id                  SERIAL PRIMARY KEY,
                    report_request_id   INTEGER,
                    sender_user_id      INTEGER NOT NULL,
                    sender_name         VARCHAR(150),
                    recipient_user_id   INTEGER,
                    content             TEXT NOT NULL,
                    type                VARCHAR(30) DEFAULT 'TEXT',
                    file_url            VARCHAR(500),
                    read_by             JSONB DEFAULT '[]',
                    created_at          TIMESTAMP DEFAULT NOW(),
                    updated_at          TIMESTAMP DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id          SERIAL PRIMARY KEY,
                    user_id     INTEGER,
                    action      VARCHAR(100) NOT NULL,
                    entity_type VARCHAR(50),
                    entity_id   VARCHAR(100),
                    details     JSONB,
                    ip_address  VARCHAR(45),
                    created_at  TIMESTAMP DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS collaborator_cache (
                    user_id      INTEGER NOT NULL PRIMARY KEY,
                    company_ids  JSONB DEFAULT '[]',
                    expires_at   TIMESTAMP,
                    last_updated TIMESTAMP DEFAULT NOW()
                );
            `);

            // Index (IF NOT EXISTS = idempotent)
            await pool.query(`
                CREATE INDEX IF NOT EXISTS idx_reports_company
                    ON financial_reports_requests(company_id);
                CREATE INDEX IF NOT EXISTS idx_reports_status
                    ON financial_reports_requests(status);
                CREATE INDEX IF NOT EXISTS idx_reports_user
                    ON financial_reports_requests(requested_by);
                CREATE INDEX IF NOT EXISTS idx_notif_recipient
                    ON notifications(recipient_user_id);
                CREATE INDEX IF NOT EXISTS idx_notif_unread
                    ON notifications(recipient_user_id) WHERE read_at IS NULL;
                CREATE INDEX IF NOT EXISTS idx_messages_request
                    ON messages(report_request_id);
                CREATE INDEX IF NOT EXISTS idx_audit_user
                    ON audit_logs(user_id);
            `);

            // Migrations douces (colonnes ajoutées si absentes)
            const migrations = [
                `ALTER TABLE financial_reports_requests
                    ADD COLUMN IF NOT EXISTS requested_by_name  VARCHAR(255)`,
                `ALTER TABLE financial_reports_requests
                    ADD COLUMN IF NOT EXISTS requested_by_email VARCHAR(255)`,
                `ALTER TABLE financial_reports_requests
                    ADD COLUMN IF NOT EXISTS assigned_to        INTEGER`,
                `ALTER TABLE financial_reports_requests
                    ADD COLUMN IF NOT EXISTS assigned_to_name   VARCHAR(255)`,
                `ALTER TABLE financial_reports_requests
                    ADD COLUMN IF NOT EXISTS rejection_reason   TEXT`,
                `ALTER TABLE financial_reports_requests
                    ADD COLUMN IF NOT EXISTS report_types       JSONB`,
            ];

            for (const migration of migrations) {
                try {
                    await pool.query(migration);
                } catch (e) {
                    // Silencieux si la colonne existe déjà
                }
            }

            console.log('✅ [DB] Tables initialisées avec succès');
            return;

        } catch (error) {
            console.warn(`⚠️ [DB] Tentative ${attempt}/${retries}: ${error.message}`);
            if (attempt < retries) {
                console.log(`   Retry dans ${delay / 1000}s...`);
                await new Promise(r => setTimeout(r, delay));
            } else {
                console.error('❌ [DB] Toutes les tentatives ont échoué.');
                console.error('   Le serveur continue mais certaines tables peuvent manquer.');
            }
        }
    }
};

// =============================================================================
// MIDDLEWARES GLOBAUX
// =============================================================================

// Headers de sécurité
app.use(securityHeaders);

// CORS sécurisé
const allowedOrigins = [
    'https://douke-compta-pro.onrender.com',
];
if (process.env.NODE_ENV !== 'production') {
    allowedOrigins.push('http://localhost:3000');
    allowedOrigins.push('http://localhost:3001');
    allowedOrigins.push('http://localhost:5173');
    allowedOrigins.push('http://127.0.0.1:3000');
}

app.use(cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        if (allowedOrigins.includes(origin)) return callback(null, true);
        console.warn(`⚠️ [CORS] Bloqué: ${origin}`);
        callback(new Error(`Origine non autorisée: ${origin}`));
    },
    credentials:    true,
    methods:        ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge:         86400,
}));

// Body parsers
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Fichiers statiques (Frontend React compilé)
app.use(express.static(path.join(__dirname, 'public')));

// Logger minimal
app.use((req, res, next) => {
    if (!req.url.startsWith('/api/health') && !req.url.startsWith('/assets')) {
        console.log(`→ ${req.method} ${req.url}`);
    }
    next();
});

// =============================================================================
// MONTAGE DES ROUTES API
// =============================================================================

console.log('🔵 Montage des routes...');

app.use('/api/auth',                        authRoutes);
app.use('/api/companies',                   companyRoutes);
app.use('/api/accounting',                  accountingRoutes);
app.use('/api/user',                        userRoutes);
app.use('/api/settings',                    settingsRoutes);
app.use('/api/admin',                       adminUsersRoutes);
app.use('/api/notifications',               notificationsRoutes);
app.use('/api/ocr',                         ocrRoutes);
app.use('/api/accounting/immobilisations',  immobilisationsRoutes);
app.use('/api/reports',                     reportsRoutes);
app.use('/api/messages',                    messagesRoutes);

console.log('✅ Toutes les routes montées');

// =============================================================================
// HEALTH CHECK
// =============================================================================

app.get('/api/health', async (req, res) => {
    let dbStatus = 'unknown';
    try {
        await pool.query('SELECT 1');
        dbStatus = 'ok';
    } catch (e) {
        dbStatus = `error: ${e.message}`;
    }

    res.json({
        success:   true,
        status:    'OK',
        version:   'V2',
        timestamp: new Date().toISOString(),
        env:       process.env.NODE_ENV || 'development',
        db:        dbStatus,
        odoo:      process.env.ODOO_URL || 'non configuré',
    });
});

// =============================================================================
// FALLBACK SPA
// =============================================================================

app.use((req, res, next) => {
    if (req.url.startsWith('/api')) {
        return res.status(404).json({
            success: false,
            error:   'Route API non trouvée.',
            path:    req.url,
            method:  req.method,
        });
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// =============================================================================
// GESTIONNAIRE D'ERREURS GLOBAL
// =============================================================================

app.use((err, req, res, next) => {
    console.error('❌ [ERREUR SERVEUR]', err.message);

    if (process.env.NODE_ENV === 'production') {
        return res.status(500).json({
            success: false,
            error:   'Erreur serveur interne. Réessayez.',
        });
    }

    res.status(err.status || 500).json({
        success:  false,
        error:    err.message,
        stack:    err.stack,
    });
});

// =============================================================================
// DÉMARRAGE DU SERVEUR
// =============================================================================

app.listen(PORT, async () => {
    console.log('');
    console.log('═'.repeat(55));
    console.log('  DOUKÈ COMPTA PRO — V2');
    console.log('═'.repeat(55));
    console.log(`  Port      : ${PORT}`);
    console.log(`  URL       : http://localhost:${PORT}`);
    console.log(`  Timestamp : ${new Date().toISOString()}`);
    console.log(`  Env       : ${process.env.NODE_ENV || 'development'}`);
    console.log(`  Odoo URL  : ${process.env.ODOO_URL}`);
    console.log(`  Odoo DB   : ${process.env.ODOO_DB}`);
    console.log(`  Admin UID : ${process.env.ODOO_ADMIN_UID}`);
    console.log('═'.repeat(55));

    // Initialisation DB
    await initDB();

    // Keep-alive (évite le cold start Render Free)
    if (process.env.NODE_ENV === 'production' || process.env.RENDER) {
        const KEEP_ALIVE_INTERVAL = 9 * 60 * 1000;

        setInterval(async () => {
            // Ping HTTP
            try {
                await fetch(`${process.env.APP_URL || 'https://douke-compta-pro.onrender.com'}/api/health`);
                console.log('🔄 [Keep-alive] Ping OK');
            } catch (e) {
                console.warn('⚠️ [Keep-alive] Ping échoué:', e.message);
            }

            // Ping PostgreSQL
            try {
                await pool.query('SELECT 1');
                console.log('🔄 [Keep-alive] DB OK');
            } catch (e) {
                console.warn('⚠️ [Keep-alive] DB échoué:', e.message);
            }

            // Nettoyage tokens révoqués expirés
            try {
                const result = await pool.query(
                    'DELETE FROM revoked_tokens WHERE expires_at < NOW()'
                );
                if (result.rowCount > 0) {
                    console.log(`🧹 ${result.rowCount} token(s) révoqué(s) nettoyé(s)`);
                }
            } catch (e) {
                // Silencieux
            }

            // Nettoyage notifications lues anciennes (> 30 jours)
            try {
                const result = await pool.query(`
                    DELETE FROM notifications
                    WHERE read_at IS NOT NULL
                    AND created_at < NOW() - INTERVAL '30 days'
                `);
                if (result.rowCount > 0) {
                    console.log(`🧹 ${result.rowCount} notification(s) ancienne(s) nettoyée(s)`);
                }
            } catch (e) {
                // Silencieux
            }

        }, KEEP_ALIVE_INTERVAL);

        console.log('✅ [Keep-alive] Activé (9 min)');
    }

    console.log('');
    console.log('✅ Serveur V2 prêt et opérationnel');
    console.log('');
});
