// =============================================================================
// FICHIER : middleware/auth.js
// Version : V2 — Compatible avec odooService.js V1 (JSON-RPC)
// Rôles   : ADMIN / COLLABORATEUR / USER / CAISSIER
// =============================================================================

const jwt    = require('jsonwebtoken');
const crypto = require('crypto');
const pool   = require('../services/dbService');
const { odooExecuteKw, ADMIN_UID_INT } = require('../services/odooService');

// =============================================================================
// CONFIGURATION
// =============================================================================

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('❌ FATAL: JWT_SECRET manquant');
    process.exit(1);
}

// =============================================================================
// CONSTANTES RÔLES
// =============================================================================

const ROLES = Object.freeze({
    ADMIN:         'ADMIN',
    COLLABORATEUR: 'COLLABORATEUR',
    USER:          'USER',
    CAISSIER:      'CAISSIER',
});

// Routes autorisées pour le CAISSIER
const CAISSIER_ROUTES = Object.freeze([
    { method: 'POST', path: '/api/accounting/caisse-entry' },
    { method: 'GET',  path: '/api/accounting/journal' },
    { method: 'GET',  path: '/api/accounting/journals' },
    { method: 'GET',  path: '/api/accounting/accounts' },
    { method: 'GET',  path: '/api/accounting/dashboard' },
    { method: 'GET',  path: '/api/accounting/dashboard/kpis' },
    { method: 'GET',  path: '/api/notifications' },
]);

// =============================================================================
// CACHE PERMISSIONS (En mémoire — TTL 5 minutes)
// Evite d'appeler Odoo à chaque requête pour vérifier les entreprises
// =============================================================================

const _permCache = new Map();
const CACHE_TTL  = 5 * 60 * 1000; // 5 minutes

const cacheGet = (userId, companyId) => {
    const key   = `${userId}:${companyId}`;
    const entry = _permCache.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) { _permCache.delete(key); return null; }
    return entry.value;
};

const cacheSet = (userId, companyId, value) => {
    const key = `${userId}:${companyId}`;
    _permCache.set(key, { value, expiresAt: Date.now() + CACHE_TTL });
};

// Nettoyage du cache toutes les 10 minutes
setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of _permCache) {
        if (now > entry.expiresAt) _permCache.delete(key);
    }
}, 10 * 60 * 1000);

// =============================================================================
// RATE LIMITER SIMPLE (Sans dépendance externe)
// =============================================================================

const _loginAttempts = new Map();

const loginRateLimit = (req, res, next) => {
    const ip    = getClientIp(req);
    const entry = _loginAttempts.get(ip);
    const now   = Date.now();

    if (entry) {
        // Fenêtre de 15 minutes
        if (now - entry.firstAttempt > 15 * 60 * 1000) {
            _loginAttempts.delete(ip);
        } else if (entry.count >= 5) {
            const waitMin = Math.ceil((15 * 60 * 1000 - (now - entry.firstAttempt)) / 60000);
            return res.status(429).json({
                success:   false,
                error:     `Trop de tentatives. Réessayez dans ${waitMin} minute(s).`,
                errorCode: 'RATE_LIMITED',
            });
        }
    }

    // Enregistre la tentative
    if (!_loginAttempts.has(ip)) {
        _loginAttempts.set(ip, { count: 1, firstAttempt: now });
    } else {
        _loginAttempts.get(ip).count++;
    }

    next();
};

// Reset après login réussi
const resetLoginAttempts = (req) => {
    const ip = getClientIp(req);
    _loginAttempts.delete(ip);
};

// Nettoyage toutes les 15 minutes
setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of _loginAttempts) {
        if (now - entry.firstAttempt > 15 * 60 * 1000) {
            _loginAttempts.delete(ip);
        }
    }
}, 15 * 60 * 1000);

// =============================================================================
// HELPERS
// =============================================================================

const getClientIp = (req) => {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim()
        || req.headers['x-real-ip']
        || req.connection?.remoteAddress
        || req.ip
        || 'unknown';
};

const hashToken = (token) => {
    return crypto.createHash('sha256').update(token).digest('hex');
};

const jsonResponse = (res, status, payload) => {
    return res.status(status).json({ success: status < 400, ...payload });
};

// =============================================================================
// AUDIT LOG (Non bloquant)
// =============================================================================

const recordAudit = async (userId, action, entityType, entityId, details, ip) => {
    try {
        await pool.query(
            `INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details, ip_address)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [userId, action, entityType, String(entityId), JSON.stringify(details || {}), ip]
        );
    } catch (err) {
        // Silencieux — l'audit ne doit jamais bloquer une opération
        console.warn('⚠️ [Audit] Échec écriture:', err.message);
    }
};

// =============================================================================
// MIDDLEWARE 1 : PROTECTION JWT
// =============================================================================

const protect = async (req, res, next) => {
    try {
        // 1. Extraction du token
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return jsonResponse(res, 401, {
                error:     'Token manquant.',
                errorCode: 'NO_TOKEN',
            });
        }

        const token = authHeader.split(' ')[1];
        if (!token || token === 'undefined' || token === 'null') {
            return jsonResponse(res, 401, {
                error:     'Token invalide.',
                errorCode: 'EMPTY_TOKEN',
            });
        }

        // 2. Vérification token révoqué
        try {
            const tokenHash = hashToken(token);
            const revoked   = await pool.query(
                'SELECT 1 FROM revoked_tokens WHERE token_hash = $1 AND expires_at > NOW()',
                [tokenHash]
            );
            if (revoked.rowCount > 0) {
                return jsonResponse(res, 401, {
                    error:     'Session révoquée. Reconnectez-vous.',
                    errorCode: 'TOKEN_REVOKED',
                });
            }
            // Stocker le hash pour la révocation future
            req._tokenHash = tokenHash;
        } catch (dbErr) {
            // Si la table n'existe pas encore, on continue
            if (!dbErr.message.includes('does not exist')) {
                console.warn('⚠️ [protect] Erreur vérification révocation:', dbErr.message);
            }
        }

        // 3. Décodage JWT
        let decoded;
        try {
            decoded = jwt.verify(token, JWT_SECRET);
        } catch (jwtErr) {
            const isExpired = jwtErr.name === 'TokenExpiredError';
            return jsonResponse(res, 401, {
                error:     isExpired ? 'Session expirée. Reconnectez-vous.' : 'Token invalide.',
                errorCode: isExpired ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN',
            });
        }

        // 4. Validation du payload
        if (!decoded.odooUid) {
            return jsonResponse(res, 401, {
                error:     'Token mal formé.',
                errorCode: 'INVALID_PAYLOAD',
            });
        }

        // 5. Normalisation du rôle
        const rawRole = (decoded.role || decoded.profile || 'USER').toUpperCase();
        const role    = Object.values(ROLES).includes(rawRole) ? rawRole : ROLES.USER;

        // 6. Injection req.user
        req.user = {
            odooUid:           decoded.odooUid,
            email:             decoded.email             || '',
            name:              decoded.name              || decoded.email || 'Utilisateur',
            role,
            profile:           role,
            selectedCompanyId: decoded.selectedCompanyId || null,
            companyId:         decoded.companyId         || decoded.selectedCompanyId || null,
            allowedCompanyIds: decoded.allowedCompanyIds || [],
        };

        next();

    } catch (err) {
        console.error('❌ [protect] Erreur inattendue:', err.message);
        return jsonResponse(res, 500, {
            error:     'Erreur interne d\'authentification.',
            errorCode: 'AUTH_ERROR',
        });
    }
};

// =============================================================================
// MIDDLEWARE 2 : VÉRIFICATION ACCÈS ENTREPRISE
// =============================================================================

const checkCompanyAccess = async (req, res, next) => {
    try {
        const { role, odooUid, email, allowedCompanyIds } = req.user;

        // Extraction du companyId depuis la requête
        const rawId = req.query.companyId
            || req.params.companyId
            || req.body?.companyId
            || req.body?.company_id;

        if (!rawId) {
            return jsonResponse(res, 400, {
                error:     'ID entreprise requis.',
                errorCode: 'MISSING_COMPANY_ID',
            });
        }

        const requestedId = parseInt(rawId, 10);
        if (isNaN(requestedId) || requestedId <= 0) {
            return jsonResponse(res, 400, {
                error:     'ID entreprise invalide.',
                errorCode: 'INVALID_COMPANY_ID',
            });
        }

        // ADMIN → accès total
        if (role === ROLES.ADMIN) {
            req.validatedCompanyId = requestedId;
            return next();
        }

        // Vérification cache
        const cached = cacheGet(odooUid, requestedId);
        if (cached !== null) {
            if (cached) {
                req.validatedCompanyId = requestedId;
                return next();
            }
            return jsonResponse(res, 403, {
                error:     'Accès refusé à cette entreprise.',
                errorCode: 'COMPANY_ACCESS_DENIED',
            });
        }

        // USER / CAISSIER → vérification depuis le token JWT
        if (role === ROLES.USER || role === ROLES.CAISSIER) {
            const hasAccess = (allowedCompanyIds || []).includes(requestedId);
            cacheSet(odooUid, requestedId, hasAccess);

            if (hasAccess) {
                req.validatedCompanyId = requestedId;
                return next();
            }
            return jsonResponse(res, 403, {
                error:     'Accès refusé à cette entreprise.',
                errorCode: 'COMPANY_ACCESS_DENIED',
            });
        }

        // COLLABORATEUR → vérification Odoo (puis cache)
        if (role === ROLES.COLLABORATEUR) {
            try {
                const userData = await odooExecuteKw({
                    uid:    ADMIN_UID_INT,
                    model:  'res.users',
                    method: 'read',
                    args:   [[odooUid], ['company_ids']],
                    kwargs: {},
                });

                if (!userData || userData.length === 0) {
                    return jsonResponse(res, 403, {
                        error:     'Utilisateur introuvable dans Odoo.',
                        errorCode: 'USER_NOT_FOUND',
                    });
                }

                const odooCompanyIds = userData[0].company_ids || [];
                const hasAccess      = odooCompanyIds.includes(requestedId);

                // Cache pour toutes ses entreprises
                odooCompanyIds.forEach(cid => cacheSet(odooUid, cid, true));
                if (!hasAccess) cacheSet(odooUid, requestedId, false);

                if (hasAccess) {
                    req.validatedCompanyId = requestedId;
                    return next();
                }

                return jsonResponse(res, 403, {
                    error:     'Cette entreprise ne vous est pas attribuée.',
                    errorCode: 'COMPANY_NOT_ASSIGNED',
                });

            } catch (odooErr) {
                console.error('⚠️ [checkCompanyAccess] Odoo error:', odooErr.message);

                // Fallback token si Odoo down
                const fallback = (allowedCompanyIds || []).includes(requestedId);
                if (fallback) {
                    req.validatedCompanyId = requestedId;
                    return next();
                }

                return jsonResponse(res, 503, {
                    error:     'Service temporairement indisponible.',
                    errorCode: 'SERVICE_UNAVAILABLE',
                });
            }
        }

        return jsonResponse(res, 403, {
            error:     'Rôle non reconnu.',
            errorCode: 'UNKNOWN_ROLE',
        });

    } catch (err) {
        console.error('❌ [checkCompanyAccess] Erreur:', err.message);
        return jsonResponse(res, 500, {
            error:     'Erreur vérification permissions.',
            errorCode: 'PERMISSION_ERROR',
        });
    }
};

// =============================================================================
// MIDDLEWARE 3 : VÉRIFICATION PERMISSIONS ÉCRITURE
// =============================================================================

const checkWritePermission = (req, res, next) => {
    const { role, email } = req.user;

    if ([ROLES.ADMIN, ROLES.COLLABORATEUR, ROLES.USER].includes(role)) {
        return next();
    }

    if (role === ROLES.CAISSIER) {
        const path     = req.originalUrl.split('?')[0];
        const method   = req.method.toUpperCase();
        const allowed  = CAISSIER_ROUTES.some(r => method === r.method && path.startsWith(r.path));

        if (allowed) return next();

        console.warn(`⚠️ [CAISSIER BLOQUÉ] ${email} → ${method} ${path}`);
        return jsonResponse(res, 403, {
            error:     'Rôle CAISSIER limité aux opérations de caisse.',
            errorCode: 'CAISSIER_RESTRICTED',
        });
    }

    return jsonResponse(res, 403, {
        error:     'Rôle non autorisé.',
        errorCode: 'ROLE_UNAUTHORIZED',
    });
};

// =============================================================================
// MIDDLEWARE 4 : RESTRICTION PAR RÔLE
// =============================================================================

const restrictTo = (...roles) => {
    const normalized = roles.map(r => r.toUpperCase());
    return (req, res, next) => {
        if (!req.user) {
            return jsonResponse(res, 401, { error: 'Non authentifié.', errorCode: 'NOT_AUTHENTICATED' });
        }
        if (!normalized.includes(req.user.role)) {
            return jsonResponse(res, 403, {
                error:     `Accès réservé aux rôles: ${normalized.join(', ')}`,
                errorCode: 'INSUFFICIENT_ROLE',
            });
        }
        next();
    };
};

// =============================================================================
// MIDDLEWARE 5 : CHECK ROLE (Alias insensible à la casse)
// =============================================================================

const checkRole = (roles) => restrictTo(...roles);

// =============================================================================
// MIDDLEWARE 6 : HEADERS DE SÉCURITÉ
// =============================================================================

const securityHeaders = (req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

    if (process.env.NODE_ENV === 'production') {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }

    next();
};

// =============================================================================
// MIDDLEWARE 7 : VÉRIFICATION ACCÈS RAPPORT (Pour les demandes de rapports)
// Vérifie que le COLLABORATEUR n'accède qu'aux entreprises qui lui sont assignées
// =============================================================================

const checkReportAccess = async (req, res, next) => {
    try {
        const requestId = parseInt(req.params.id);
        const userId    = req.user.odooUid;
        const role      = req.user.role;

        if (!requestId || isNaN(requestId)) {
            return jsonResponse(res, 400, {
                error:     'ID de demande invalide.',
                errorCode: 'INVALID_REQUEST_ID',
            });
        }

        // Récupérer la demande
        const result = await pool.query(
            'SELECT id, company_id, requested_by, status FROM financial_reports_requests WHERE id = $1',
            [requestId]
        );

        if (result.rows.length === 0) {
            return jsonResponse(res, 404, {
                error:     'Demande introuvable.',
                errorCode: 'REQUEST_NOT_FOUND',
            });
        }

        const report = result.rows[0];

        // ADMIN → accès total
        if (role === ROLES.ADMIN) {
            req.reportRequest = report;
            return next();
        }

        // COLLABORATEUR → vérifier que l'entreprise lui est assignée
        if (role === ROLES.COLLABORATEUR) {
            const cached = cacheGet(userId, report.company_id);

            let hasAccess = cached;

            if (cached === null) {
                try {
                    const userData = await odooExecuteKw({
                        uid:    ADMIN_UID_INT,
                        model:  'res.users',
                        method: 'read',
                        args:   [[userId], ['company_ids']],
                        kwargs: {},
                    });
                    const companyIds = userData?.[0]?.company_ids || [];
                    hasAccess = companyIds.includes(report.company_id);
                    cacheSet(userId, report.company_id, hasAccess);
                } catch (e) {
                    console.error('⚠️ [checkReportAccess] Odoo error:', e.message);
                    hasAccess = (req.user.allowedCompanyIds || []).includes(report.company_id);
                }
            }

            if (!hasAccess) {
                return jsonResponse(res, 403, {
                    error:     'Cette demande concerne une entreprise qui ne vous est pas attribuée.',
                    errorCode: 'COMPANY_NOT_ASSIGNED',
                });
            }

            req.reportRequest = report;
            return next();
        }

        // USER / CAISSIER → seulement ses propres demandes
        if (report.requested_by !== userId) {
            return jsonResponse(res, 403, {
                error:     'Cette demande ne vous appartient pas.',
                errorCode: 'NOT_YOUR_REQUEST',
            });
        }

        req.reportRequest = report;
        next();

    } catch (err) {
        console.error('❌ [checkReportAccess]', err.message);
        return jsonResponse(res, 500, {
            error:     'Erreur vérification accès rapport.',
            errorCode: 'REPORT_ACCESS_ERROR',
        });
    }
};

// =============================================================================
// FONCTION : RÉVOQUER UN TOKEN
// =============================================================================

const revokeToken = async (tokenHash, expiresAtUnix) => {
    try {
        const expiresAt = new Date(expiresAtUnix * 1000);
        await pool.query(
            `INSERT INTO revoked_tokens (token_hash, expires_at)
             VALUES ($1, $2) ON CONFLICT (token_hash) DO NOTHING`,
            [tokenHash, expiresAt]
        );
        return true;
    } catch (err) {
        console.warn('⚠️ [revokeToken]', err.message);
        return false;
    }
};

// =============================================================================
// EXPORTS
// =============================================================================

module.exports = {
    // Middlewares principaux
    protect,
    checkCompanyAccess,
    checkWritePermission,
    restrictTo,
    checkRole,
    securityHeaders,
    checkReportAccess,
    loginRateLimit,

    // Alias compatibilité V1
    authenticateToken: protect,

    // Utilitaires
    revokeToken,
    recordAudit,
    getClientIp,
    hashToken,
    resetLoginAttempts,

    // Constantes
    ROLES,
};

console.log('✅ [middleware/auth.js] Chargé — Rôles: ADMIN | COLLABORATEUR | USER | CAISSIER');
