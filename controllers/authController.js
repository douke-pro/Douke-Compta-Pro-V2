// =============================================================================
// FICHIER : controllers/authController.js
// Version : V2 — Compatible odooService.js V1 (JSON-RPC)
// Rôles   : ADMIN / COLLABORATEUR / USER / CAISSIER
// =============================================================================

const jwt = require('jsonwebtoken');
const { odooAuthenticate, odooExecuteKw, ADMIN_UID_INT } = require('../services/odooService');
const {
    revokeToken,
    recordAudit,
    getClientIp,
    hashToken,
    resetLoginAttempts,
    ROLES,
} = require('../middleware/auth');

// =============================================================================
// CONFIGURATION
// =============================================================================

const JWT_SECRET    = process.env.JWT_SECRET;
const JWT_EXPIRES   = process.env.JWT_EXPIRES_IN || '24h';

if (!JWT_SECRET) {
    console.error('❌ FATAL [authController]: JWT_SECRET manquant');
    process.exit(1);
}

// =============================================================================
// HELPERS PRIVÉS
// =============================================================================

/**
 * Génère un token JWT
 */
const signToken = (payload) => {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES });
};

/**
 * Réponse uniforme
 */
const ok   = (res, data, code = 200) => res.status(code).json({ success: true,  ...data });
const fail = (res, code, msg, errCode = 'ERROR') =>
    res.status(code).json({ success: false, error: msg, errorCode: errCode });

/**
 * Récupère le vrai nom + les company_ids d'un utilisateur Odoo
 */
const fetchOdooUser = async (uid) => {
    const data = await odooExecuteKw({
        uid:    ADMIN_UID_INT,
        model:  'res.users',
        method: 'read',
        args:   [[uid], ['name', 'company_ids']],
        kwargs: {},
    });

    if (!data || data.length === 0) {
        throw new Error('Utilisateur introuvable dans Odoo.');
    }

    return {
        name:       data[0].name       || '',
        companyIds: data[0].company_ids || [],
    };
};

/**
 * Récupère les entreprises depuis Odoo
 * ADMIN → toutes les entreprises
 * Autres → uniquement celles assignées
 */
const fetchCompanies = async (role, companyIds) => {
    const domain = role === ROLES.ADMIN
        ? [[]]
        : [[['id', 'in', companyIds]]];

    const companies = await odooExecuteKw({
        uid:    ADMIN_UID_INT,
        model:  'res.company',
        method: 'search_read',
        args:   domain,
        kwargs: {
            fields: ['id', 'name', 'currency_id'],
            limit:  100,
        },
    });

    return (companies || []).map(c => ({
        id:       c.id,
        name:     c.name,
        systeme:  'NORMAL',
        currency: c.currency_id ? c.currency_id[1] : 'XOF',
    }));
};

/**
 * Valide un email
 */
const isValidEmail = (email) =>
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || '').trim());

// =============================================================================
// 1. CONNEXION
// POST /api/auth/login
// =============================================================================

exports.loginUser = async (req, res) => {
    const { email, password } = req.body;
    const clientIp = getClientIp(req);

    // Validation entrées
    if (!email || !password) {
        return fail(res, 400, 'Email et mot de passe requis.', 'MISSING_CREDENTIALS');
    }
    if (!isValidEmail(email)) {
        return fail(res, 400, 'Format email invalide.', 'INVALID_EMAIL');
    }

    try {
        // 1. Authentification Odoo (JSON-RPC via ton odooService.js)
        let authResult;
        try {
            authResult = await odooAuthenticate(email, password);
        } catch (odooErr) {
            await recordAudit(null, 'LOGIN_FAILED', 'USER', null, {
                email, reason: odooErr.message,
            }, clientIp);

            return fail(res, 401, 'Email ou mot de passe incorrect.', 'INVALID_CREDENTIALS');
        }

        const { uid, profile } = authResult;

        if (!uid) {
            return fail(res, 401, 'Identifiants invalides.', 'INVALID_CREDENTIALS');
        }

        // 2. Récupération nom réel + entreprises depuis Odoo
        const { name: realName, companyIds } = await fetchOdooUser(uid);

        if (!companyIds || companyIds.length === 0) {
            return fail(res, 401, 'Aucune entreprise assignée à cet utilisateur.', 'NO_COMPANIES');
        }

        // 3. Résolution du rôle
        const resolvedRole = Object.values(ROLES).includes((profile || '').toUpperCase())
            ? profile.toUpperCase()
            : ROLES.USER;

        // 4. Liste des entreprises accessibles
        const companiesList = await fetchCompanies(resolvedRole, companyIds);

        if (companiesList.length === 0) {
            return fail(res, 401, 'Aucun dossier comptable actif trouvé.', 'NO_COMPANIES');
        }

        const defaultCompany = companiesList[0];

        // 5. Génération du JWT
        const token = signToken({
            odooUid:           uid,
            email,
            name:              realName,
            role:              resolvedRole,
            profile:           resolvedRole,
            allowedCompanyIds: companiesList.map(c => c.id),
            selectedCompanyId: defaultCompany.id,
            companyId:         defaultCompany.id,
        });

        // 6. Reset rate limiter + audit
        resetLoginAttempts(req);
        await recordAudit(uid, 'LOGIN_SUCCESS', 'USER', uid, {
            email, role: resolvedRole, companies: companiesList.length,
        }, clientIp);

        console.log(`✅ [login] ${realName} (${email}) — ${resolvedRole} — ${companiesList.length} entreprise(s)`);

        // 7. Réponse
        return ok(res, {
            status: 'success',
            data: {
                token,
                profile:        resolvedRole,
                name:           realName,
                email,
                companiesList,
                defaultCompany,
            },
        });

    } catch (err) {
        console.error('❌ [loginUser]', err.message);
        await recordAudit(null, 'LOGIN_ERROR', 'USER', null, {
            email, error: err.message,
        }, clientIp);
        return fail(res, 500, 'Erreur interne lors de la connexion.', 'LOGIN_ERROR');
    }
};

// =============================================================================
// 2. INSCRIPTION
// POST /api/auth/register
// =============================================================================

exports.registerUser = async (req, res) => {
    const { name, email, password, companyName } = req.body;
    const clientIp = getClientIp(req);

    console.log(`📝 [register] ${name} | ${email} | ${companyName}`);

    // Validation
    const errors = [];
    if (!name || name.trim().length < 2)        errors.push('Nom requis (min. 2 caractères).');
    if (!email || !isValidEmail(email))          errors.push('Email invalide.');
    if (!password || password.length < 8)        errors.push('Mot de passe min. 8 caractères.');
    if (!companyName || companyName.trim().length < 2) errors.push('Nom entreprise requis.');

    if (errors.length > 0) {
        return fail(res, 400, errors.join(' '), 'VALIDATION_ERROR');
    }

    try {
        // 1. Email déjà utilisé ?
        const existing = await odooExecuteKw({
            uid:    ADMIN_UID_INT,
            model:  'res.users',
            method: 'search_read',
            args:   [[['login', '=', email.trim()]]],
            kwargs: { fields: ['id'], limit: 1 },
        });

        if (existing && existing.length > 0) {
            return fail(res, 409, 'Cet email est déjà utilisé.', 'EMAIL_EXISTS');
        }

        // 2. Créer l'entreprise dans Odoo
        console.log(`   🏢 Création entreprise: ${companyName}`);

        const companyId = await odooExecuteKw({
            uid:    ADMIN_UID_INT,
            model:  'res.company',
            method: 'create',
            args:   [{ name: companyName.trim(), currency_id: 1 }],
            kwargs: {},
        });

        if (!companyId || typeof companyId !== 'number') {
            throw new Error('Échec création entreprise Odoo.');
        }

        console.log(`   ✅ Entreprise créée ID: ${companyId}`);

        // 3. Créer l'utilisateur dans Odoo
        console.log(`   👤 Création utilisateur: ${name}`);

        const newUid = await odooExecuteKw({
            uid:    ADMIN_UID_INT,
            model:  'res.users',
            method: 'create',
            args:   [{
                name:        name.trim(),
                login:       email.trim(),
                email:       email.trim(),
                password:    password,
                active:      true,
                company_id:  companyId,
                company_ids: [[6, 0, [companyId]]],
            }],
            kwargs: {},
        });

        if (!newUid || typeof newUid !== 'number') {
            throw new Error('Échec création utilisateur Odoo.');
        }

        console.log(`   ✅ Utilisateur créé UID: ${newUid}`);

        // 4. Groupes de base (non bloquant)
        try {
            const groups = await odooExecuteKw({
                uid:    ADMIN_UID_INT,
                model:  'res.groups',
                method: 'search_read',
                args:   [[['name', '=', 'User']]],
                kwargs: { fields: ['id'], limit: 1 },
            });
            if (groups && groups.length > 0) {
                await odooExecuteKw({
                    uid:    ADMIN_UID_INT,
                    model:  'res.groups',
                    method: 'write',
                    args:   [[groups[0].id], { users: [[4, newUid]] }],
                    kwargs: {},
                });
            }
        } catch (groupErr) {
            console.warn('   ⚠️ Groupes non assignés (non bloquant):', groupErr.message);
        }

        // 5. Génération du JWT
        const defaultCompany = {
            id:       companyId,
            name:     companyName.trim(),
            systeme:  'NORMAL',
            currency: 'XOF',
        };

        const token = signToken({
            odooUid:           newUid,
            email:             email.trim(),
            name:              name.trim(),
            role:              ROLES.ADMIN,
            profile:           ROLES.ADMIN,
            allowedCompanyIds: [companyId],
            selectedCompanyId: companyId,
            companyId:         companyId,
        });

        // 6. Audit
        await recordAudit(newUid, 'REGISTER_SUCCESS', 'USER', newUid, {
            email, companyId, companyName: companyName.trim(),
        }, clientIp);

        console.log(`✅ [register] Succès: ${name} | ${email} | ${companyName}`);

        return ok(res, {
            status:  'success',
            message: `Compte créé avec succès ! Bienvenue ${name.trim()}.`,
            data: {
                token,
                profile:       ROLES.ADMIN,
                name:          name.trim(),
                email:         email.trim(),
                companiesList: [defaultCompany],
                defaultCompany,
            },
        }, 201);

    } catch (err) {
        console.error('❌ [registerUser]', err.message);
        await recordAudit(null, 'REGISTER_ERROR', 'USER', null, {
            email, error: err.message,
        }, clientIp);
        return fail(res, 500, `Erreur création compte: ${err.message}`, 'REGISTER_ERROR');
    }
};

// =============================================================================
// 3. PROFIL UTILISATEUR
// GET /api/auth/me
// =============================================================================

exports.getMe = async (req, res) => {
    if (!req.user) {
        return fail(res, 401, 'Non authentifié.', 'NOT_AUTHENTICATED');
    }

    try {
        const { odooUid, email, role, selectedCompanyId } = req.user;

        // Récupérer les données fraîches depuis Odoo
        const { name: realName, companyIds } = await fetchOdooUser(odooUid);

        if (!companyIds || companyIds.length === 0) {
            return fail(res, 401, 'Aucune entreprise active.', 'NO_COMPANIES');
        }

        const companiesList  = await fetchCompanies(role, companyIds);
        const currentCompany = companiesList.find(c => c.id === selectedCompanyId);

        return ok(res, {
            status: 'success',
            data: {
                profile:             role,
                name:                realName,
                email,
                odooUid,
                companiesList,
                selectedCompanyId,
                currentCompanyName:  currentCompany?.name || 'N/A',
            },
        });

    } catch (err) {
        console.error('❌ [getMe]', err.message);
        return fail(res, 500, err.message, 'GET_ME_ERROR');
    }
};

// =============================================================================
// 4. DÉCONNEXION AVEC RÉVOCATION RÉELLE
// POST /api/auth/force-logout
// =============================================================================

exports.forceLogout = async (req, res) => {
    try {
        const { odooUid, email } = req.user;
        const clientIp           = getClientIp(req);

        // Extraire et révoquer le token
        const token = req.headers.authorization?.split(' ')[1];
        if (token && req._tokenHash) {
            const decoded = jwt.decode(token);
            if (decoded?.exp) {
                await revokeToken(req._tokenHash, decoded.exp);
            }
        }

        await recordAudit(odooUid, 'LOGOUT', 'USER', odooUid, { email }, clientIp);

        console.log(`✅ [logout] ${email} déconnecté`);

        return ok(res, {
            status:  'success',
            message: 'Déconnexion réussie. Session invalidée.',
        });

    } catch (err) {
        console.error('❌ [forceLogout]', err.message);
        // On répond succès même en cas d'erreur (le client supprime le token)
        return ok(res, {
            status:  'success',
            message: 'Déconnexion effectuée.',
        });
    }
};

// =============================================================================
// 5. CHANGER D'ENTREPRISE ACTIVE
// POST /api/auth/switch-company
// =============================================================================

exports.switchCompany = async (req, res) => {
    try {
        const { companyId }                    = req.body;
        const { odooUid, email, name, role }   = req.user;
        const clientIp                         = getClientIp(req);

        if (!companyId || isNaN(parseInt(companyId, 10))) {
            return fail(res, 400, 'ID entreprise requis.', 'MISSING_COMPANY_ID');
        }

        const targetId = parseInt(companyId, 10);

        // Récupérer les entreprises disponibles selon le rôle
        const { companyIds } = await fetchOdooUser(odooUid);
        const companiesList  = await fetchCompanies(role, companyIds);

        // Vérifier que l'entreprise cible est accessible
        const targetCompany = companiesList.find(c => c.id === targetId);
        if (!targetCompany && role !== ROLES.ADMIN) {
            return fail(res, 403, 'Accès refusé à cette entreprise.', 'COMPANY_ACCESS_DENIED');
        }

        // Si ADMIN, récupérer le détail de l'entreprise même si pas dans la liste
        let finalCompany = targetCompany;
        if (!finalCompany) {
            const compData = await odooExecuteKw({
                uid:    ADMIN_UID_INT,
                model:  'res.company',
                method: 'read',
                args:   [[targetId], ['id', 'name', 'currency_id']],
                kwargs: {},
            });
            if (!compData || compData.length === 0) {
                return fail(res, 404, 'Entreprise introuvable.', 'COMPANY_NOT_FOUND');
            }
            finalCompany = {
                id:       compData[0].id,
                name:     compData[0].name,
                systeme:  'NORMAL',
                currency: compData[0].currency_id?.[1] || 'XOF',
            };
        }

        // Révoquer l'ancien token
        const oldToken = req.headers.authorization?.split(' ')[1];
        if (oldToken && req._tokenHash) {
            const decoded = jwt.decode(oldToken);
            if (decoded?.exp) await revokeToken(req._tokenHash, decoded.exp);
        }

        // Nouveau token avec la nouvelle entreprise
        const newToken = signToken({
            odooUid,
            email,
            name,
            role,
            profile:           role,
            allowedCompanyIds: companiesList.map(c => c.id),
            selectedCompanyId: targetId,
            companyId:         targetId,
        });

        await recordAudit(odooUid, 'SWITCH_COMPANY', 'COMPANY', targetId, {
            from: req.user.selectedCompanyId,
            to:   targetId,
            companyName: finalCompany.name,
        }, clientIp);

        console.log(`✅ [switchCompany] ${email} → ${finalCompany.name}`);

        return ok(res, {
            status:  'success',
            message: `Entreprise changée vers "${finalCompany.name}".`,
            data: {
                token:           newToken,
                selectedCompany: finalCompany,
                companiesList,
            },
        });

    } catch (err) {
        console.error('❌ [switchCompany]', err.message);
        return fail(res, 500, err.message, 'SWITCH_COMPANY_ERROR');
    }
};

// =============================================================================
// 6. ATTRIBUER DES ENTREPRISES (ADMIN UNIQUEMENT)
// POST /api/auth/assign-company
// =============================================================================

exports.assignCompany = async (req, res) => {
    try {
        const { userId, companyIds }               = req.body;
        const { odooUid: adminUid, name: adminName } = req.user;
        const clientIp                             = getClientIp(req);

        // Validation
        if (!userId || !companyIds || !Array.isArray(companyIds) || companyIds.length === 0) {
            return fail(res, 400, 'userId et companyIds (tableau) requis.', 'MISSING_PARAMS');
        }

        const targetUserId    = parseInt(userId, 10);
        const targetCompanyIds = companyIds.map(id => parseInt(id, 10));

        if (isNaN(targetUserId) || targetCompanyIds.some(isNaN)) {
            return fail(res, 400, 'IDs invalides.', 'INVALID_IDS');
        }

        // Vérifier que l'utilisateur cible existe dans Odoo
        const targetUser = await odooExecuteKw({
            uid:    ADMIN_UID_INT,
            model:  'res.users',
            method: 'read',
            args:   [[targetUserId], ['name', 'login', 'company_ids']],
            kwargs: {},
        });

        if (!targetUser || targetUser.length === 0) {
            return fail(res, 404, 'Utilisateur cible introuvable.', 'USER_NOT_FOUND');
        }

        // Vérifier que les entreprises existent dans Odoo
        const companiesCheck = await odooExecuteKw({
            uid:    ADMIN_UID_INT,
            model:  'res.company',
            method: 'search_read',
            args:   [[['id', 'in', targetCompanyIds]]],
            kwargs: { fields: ['id', 'name'] },
        });

        if (companiesCheck.length !== targetCompanyIds.length) {
            const found   = companiesCheck.map(c => c.id);
            const missing = targetCompanyIds.filter(id => !found.includes(id));
            return fail(res, 400, `Entreprise(s) introuvable(s): ${missing.join(', ')}`, 'COMPANIES_NOT_FOUND');
        }

        // Assigner dans Odoo ([6, 0, ids] = remplace la liste complète)
        await odooExecuteKw({
            uid:    ADMIN_UID_INT,
            model:  'res.users',
            method: 'write',
            args:   [[targetUserId], {
                company_ids: [[6, 0, targetCompanyIds]],
                company_id:  targetCompanyIds[0],
            }],
            kwargs: {},
        });

        await recordAudit(adminUid, 'ASSIGN_COMPANY', 'USER', targetUserId, {
            adminName,
            targetEmail:   targetUser[0].login,
            targetName:    targetUser[0].name,
            newCompanyIds: targetCompanyIds,
            companyNames:  companiesCheck.map(c => c.name),
        }, clientIp);

        console.log(`✅ [assignCompany] ${adminName} → ${targetUser[0].name}: ${companiesCheck.map(c => c.name).join(', ')}`);

        return ok(res, {
            status:  'success',
            message: `${companiesCheck.length} entreprise(s) attribuée(s) à ${targetUser[0].name}.`,
            data: {
                userId:    targetUserId,
                userName:  targetUser[0].name,
                companies: companiesCheck.map(c => ({ id: c.id, name: c.name })),
            },
        });

    } catch (err) {
        console.error('❌ [assignCompany]', err.message);
        return fail(res, 500, err.message, 'ASSIGN_ERROR');
    }
};

// =============================================================================
// 7. CHANGER LE MOT DE PASSE
// POST /api/auth/change-password
// =============================================================================

exports.changePassword = async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const { odooUid, email }               = req.user;
        const clientIp                         = getClientIp(req);

        // Validation
        if (!currentPassword || !newPassword) {
            return fail(res, 400, 'Mot de passe actuel et nouveau requis.', 'MISSING_PASSWORDS');
        }
        if (newPassword.length < 8) {
            return fail(res, 400, 'Nouveau mot de passe min. 8 caractères.', 'PASSWORD_TOO_SHORT');
        }
        if (currentPassword === newPassword) {
            return fail(res, 400, 'Le nouveau mot de passe doit être différent.', 'SAME_PASSWORD');
        }

        // Vérifier le mot de passe actuel via Odoo
        try {
            await odooAuthenticate(email, currentPassword);
        } catch {
            await recordAudit(odooUid, 'CHANGE_PASSWORD_FAILED', 'USER', odooUid, { email }, clientIp);
            return fail(res, 401, 'Mot de passe actuel incorrect.', 'WRONG_PASSWORD');
        }

        // Changer le mot de passe dans Odoo
        await odooExecuteKw({
            uid:    ADMIN_UID_INT,
            model:  'res.users',
            method: 'write',
            args:   [[odooUid], { password: newPassword }],
            kwargs: {},
        });

        // Révoquer le token actuel (forcer reconnexion)
        const token = req.headers.authorization?.split(' ')[1];
        if (token && req._tokenHash) {
            const decoded = jwt.decode(token);
            if (decoded?.exp) await revokeToken(req._tokenHash, decoded.exp);
        }

        await recordAudit(odooUid, 'CHANGE_PASSWORD_SUCCESS', 'USER', odooUid, { email }, clientIp);

        console.log(`✅ [changePassword] ${email}`);

        return ok(res, {
            status:  'success',
            message: 'Mot de passe modifié. Veuillez vous reconnecter.',
        });

    } catch (err) {
        console.error('❌ [changePassword]', err.message);
        return fail(res, 500, err.message, 'CHANGE_PASSWORD_ERROR');
    }
};
