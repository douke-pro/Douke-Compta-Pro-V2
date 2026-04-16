// =============================================================================
// FICHIER : routes/auth.js
// Version : V2 — Routes d'authentification complètes
// =============================================================================

const express = require('express');
const router  = express.Router();

const {
    protect,
    restrictTo,
    loginRateLimit,
    recordAudit,
    getClientIp,
} = require('../middleware/auth');

const {
    loginUser,
    registerUser,
    getMe,
    forceLogout,
    switchCompany,
    assignCompany,
    changePassword,
} = require('../controllers/authController');

// =============================================================================
// ROUTES PUBLIQUES (Sans authentification)
// =============================================================================

/**
 * POST /api/auth/register
 * Inscription : Crée un utilisateur + une entreprise dans Odoo
 */
router.post('/register', registerUser);

/**
 * POST /api/auth/login
 * Connexion : JWT + Validation Odoo JSON-RPC
 * Rate limité : 5 tentatives / 15 minutes par IP
 */
router.post('/login', loginRateLimit, loginUser);

// =============================================================================
// ROUTES PROTÉGÉES (JWT requis)
// =============================================================================

/**
 * GET /api/auth/me
 * Récupère le profil de l'utilisateur connecté (données fraîches depuis Odoo)
 */
router.get('/me', protect, getMe);

/**
 * POST /api/auth/force-logout
 * Déconnexion avec révocation réelle du token dans revoked_tokens
 */
router.post('/force-logout', protect, forceLogout);

/**
 * POST /api/auth/switch-company
 * Change l'entreprise active — Génère un nouveau JWT
 * Body : { companyId: number }
 */
router.post('/switch-company', protect, switchCompany);

/**
 * POST /api/auth/change-password
 * Change le mot de passe dans Odoo et révoque le token actuel
 * Body : { currentPassword: string, newPassword: string }
 */
router.post('/change-password', protect, changePassword);

// =============================================================================
// ROUTES ADMIN UNIQUEMENT
// =============================================================================

/**
 * POST /api/auth/assign-company
 * Attribue des entreprises à un collaborateur
 * Body : { userId: number, companyIds: number[] }
 * Seul un ADMIN peut exécuter cette action
 */
router.post(
    '/assign-company',
    protect,
    restrictTo('ADMIN'),
    assignCompany
);

// =============================================================================
// EXPORT
// =============================================================================

module.exports = router;
