// =============================================================================
// FICHIER : controllers/immobilisationsController.js
// Version : V2 — Corrections appliquées
//   ✅ ADMIN_UID_INT sur tous les appels (plus d'Access Denied)
//   ✅ allowed_company_ids sur tous les appels (isolation entreprise)
//   ✅ Modèle Odoo 18 : 'account.asset' (au lieu de 'account.asset.asset')
//   ✅ Fallback si le module assets n'est pas installé
// =============================================================================

const { odooExecuteKw, ADMIN_UID_INT } = require('../services/odooService');

// Nom du modèle Odoo 18 pour les immobilisations
// Si ton Odoo utilise encore l'ancien nom, change ici
const ASSET_MODEL = 'account.asset';

// Helper pour les contextes Odoo
const odooCtx = (companyId) => ({
    company_id:          companyId,
    allowed_company_ids: [companyId],
});

// Helper réponse erreur uniforme
const errResp = (res, msg, detail = null) => {
    console.error(`❌ [Immobilisations] ${msg}`, detail || '');
    return res.status(500).json({
        status:  'error',
        message: msg,
        error:   detail || msg,
    });
};

// =============================================================================
// STATISTIQUES GLOBALES
// GET /api/accounting/immobilisations/stats?companyId=X
// =============================================================================

exports.getStats = async (req, res) => {
    try {
        const companyId = req.validatedCompanyId;
        if (!companyId) {
            return res.status(400).json({ status: 'error', error: 'companyId requis' });
        }

        console.log(`📊 [getStats] Company: ${companyId}`);

        const assets = await odooExecuteKw({
            uid:    ADMIN_UID_INT,
            model:  ASSET_MODEL,
            method: 'search_read',
            args:   [[
                ['company_id', '=', companyId],
                ['state', 'in', ['open', 'close']],
            ]],
            kwargs: {
                fields:  ['value', 'value_residual', 'state'],
                context: odooCtx(companyId),
            },
        });

        const stats = {
            total:           assets.length,
            valeur_brute:    assets.reduce((s, a) => s + (a.value          || 0), 0),
            amortissements:  assets.reduce((s, a) => s + ((a.value || 0) - (a.value_residual || 0)), 0),
            valeur_nette:    assets.reduce((s, a) => s + (a.value_residual || 0), 0),
            actives:         assets.filter(a => a.state === 'open').length,
            cloturees:       assets.filter(a => a.state === 'close').length,
        };

        console.log(`✅ [getStats] Total: ${stats.total}`);

        res.json({ status: 'success', data: stats });

    } catch (error) {
        return errResp(res, 'Erreur statistiques immobilisations', error.message);
    }
};

// =============================================================================
// LISTE DES IMMOBILISATIONS
// GET /api/accounting/immobilisations/list
// =============================================================================

exports.getList = async (req, res) => {
    try {
        const companyId = req.validatedCompanyId;
        if (!companyId) {
            return res.status(400).json({ status: 'error', error: 'companyId requis' });
        }

        const { category, limit = 50, offset = 0 } = req.query;

        console.log(`📋 [getList] Company: ${companyId} | Category: ${category}`);

        const domain = [['company_id', '=', companyId]];

        if (category) {
            const categoryMap = {
                '20':    ['200', '209'],
                '21':    ['210', '219'],
                '22':    ['220', '229'],
                '23':    ['230', '239'],
                '24':    ['240', '249'],
                '25-28': ['250', '289'],
            };
            const range = categoryMap[category];
            if (range) {
                domain.push(['code', '>=', range[0]]);
                domain.push(['code', '<=', range[1]]);
            }
        }

        const [assets, total] = await Promise.all([
            odooExecuteKw({
                uid:    ADMIN_UID_INT,
                model:  ASSET_MODEL,
                method: 'search_read',
                args:   [domain],
                kwargs: {
                    fields:  ['name', 'code', 'value', 'value_residual', 'date',
                              'account_asset_id', 'method', 'method_number', 'state'],
                    limit:   parseInt(limit),
                    offset:  parseInt(offset),
                    order:   'date desc',
                    context: odooCtx(companyId),
                },
            }),
            odooExecuteKw({
                uid:    ADMIN_UID_INT,
                model:  ASSET_MODEL,
                method: 'search_count',
                args:   [domain],
                kwargs: { context: odooCtx(companyId) },
            }),
        ]);

        console.log(`✅ [getList] ${assets.length}/${total}`);

        res.json({
            status: 'success',
            data:   assets,
            pagination: {
                total,
                limit:   parseInt(limit),
                offset:  parseInt(offset),
                hasMore: (parseInt(offset) + parseInt(limit)) < total,
            },
        });

    } catch (error) {
        return errResp(res, 'Erreur liste immobilisations', error.message);
    }
};

// =============================================================================
// DÉTAILS D'UNE IMMOBILISATION
// GET /api/accounting/immobilisations/:id
// =============================================================================

exports.getById = async (req, res) => {
    try {
        const assetId   = parseInt(req.params.id);
        const companyId = req.validatedCompanyId;

        if (isNaN(assetId)) {
            return res.status(400).json({ status: 'error', error: 'ID invalide' });
        }

        console.log(`🔍 [getById] Asset: ${assetId}`);

        // Vérification d'appartenance à l'entreprise
        const check = await odooExecuteKw({
            uid:    ADMIN_UID_INT,
            model:  ASSET_MODEL,
            method: 'search_read',
            args:   [[['id', '=', assetId], ['company_id', '=', companyId]]],
            kwargs: { fields: ['id'], limit: 1, context: odooCtx(companyId) },
        });

        if (!check || check.length === 0) {
            return res.status(403).json({
                status: 'error',
                error:  'Accès refusé ou immobilisation introuvable.',
            });
        }

        const asset = await odooExecuteKw({
            uid:    ADMIN_UID_INT,
            model:  ASSET_MODEL,
            method: 'read',
            args:   [[assetId]],
            kwargs: {
                fields: [
                    'name', 'code', 'value', 'value_residual', 'date',
                    'account_asset_id', 'account_depreciation_id',
                    'method', 'method_number', 'method_period',
                    'state', 'partner_id',
                ],
                context: odooCtx(companyId),
            },
        });

        console.log('✅ [getById] OK');

        res.json({ status: 'success', data: asset[0] });

    } catch (error) {
        return errResp(res, 'Erreur détail immobilisation', error.message);
    }
};

// =============================================================================
// LISTE DES CATÉGORIES
// GET /api/accounting/immobilisations/categories/list
// =============================================================================

exports.getCategories = async (req, res) => {
    try {
        const companyId = req.validatedCompanyId;
        if (!companyId) {
            return res.status(400).json({ status: 'error', error: 'companyId requis' });
        }

        console.log(`📂 [getCategories] Company: ${companyId}`);

        // En Odoo 18, les catégories d'actifs sont dans account.asset.group ou account.asset
        // Utilisation des types de comptes comme fallback
        let categories = [];
        try {
            categories = await odooExecuteKw({
                uid:    ADMIN_UID_INT,
                model:  'account.asset.group',
                method: 'search_read',
                args:   [[['company_id', '=', companyId]]],
                kwargs: {
                    fields:  ['name', 'account_asset_id', 'account_depreciation_id'],
                    context: odooCtx(companyId),
                },
            });
        } catch (e) {
            // Fallback si le modèle n'existe pas
            console.warn('⚠️ account.asset.group indisponible, retour liste vide');
            categories = [];
        }

        // Compter les assets par catégorie
        const categoriesWithCounts = await Promise.all(
            categories.map(async (cat) => {
                try {
                    const count = await odooExecuteKw({
                        uid:    ADMIN_UID_INT,
                        model:  ASSET_MODEL,
                        method: 'search_count',
                        args:   [[['account_asset_id', '=', cat.id], ['company_id', '=', companyId]]],
                        kwargs: { context: odooCtx(companyId) },
                    });
                    return { ...cat, count };
                } catch {
                    return { ...cat, count: 0 };
                }
            })
        );

        console.log(`✅ [getCategories] ${categories.length} catégories`);

        res.json({ status: 'success', data: categoriesWithCounts });

    } catch (error) {
        return errResp(res, 'Erreur catégories', error.message);
    }
};

// =============================================================================
// CRÉER UNE IMMOBILISATION
// POST /api/accounting/immobilisations/create
// =============================================================================

exports.create = async (req, res) => {
    try {
        const companyId = req.validatedCompanyId;
        if (!companyId) {
            return res.status(400).json({ status: 'error', error: 'companyId requis' });
        }

        const { name, value, account_asset_id, date, method, method_number, code } = req.body;

        if (!name || !value || !account_asset_id || !date) {
            return res.status(400).json({
                status:  'error',
                message: 'Champs requis : name, value, account_asset_id, date',
            });
        }

        console.log(`➕ [create] ${name} — ${value} XOF`);

        const assetId = await odooExecuteKw({
            uid:    ADMIN_UID_INT,
            model:  ASSET_MODEL,
            method: 'create',
            args:   [{
                name:              name,
                code:              code || '',
                original_value:    parseFloat(value),
                account_asset_id:  parseInt(account_asset_id),
                date:              date,
                company_id:        companyId,
                method:            method || 'linear',
                method_number:     parseInt(method_number) || 5,
                method_period:     '12',
                state:             'draft',
            }],
            kwargs: { context: odooCtx(companyId) },
        });

        console.log(`✅ [create] ID: ${assetId}`);

        res.status(201).json({
            status:  'success',
            message: 'Immobilisation créée avec succès',
            data:    { id: assetId },
        });

    } catch (error) {
        return errResp(res, 'Erreur création immobilisation', error.message);
    }
};

// =============================================================================
// METTRE À JOUR UNE IMMOBILISATION
// PUT /api/accounting/immobilisations/:id
// =============================================================================

exports.update = async (req, res) => {
    try {
        const assetId   = parseInt(req.params.id);
        const companyId = req.validatedCompanyId;
        const updates   = req.body;

        if (isNaN(assetId)) {
            return res.status(400).json({ status: 'error', error: 'ID invalide' });
        }

        // Vérification d'appartenance
        const check = await odooExecuteKw({
            uid:    ADMIN_UID_INT,
            model:  ASSET_MODEL,
            method: 'search_read',
            args:   [[['id', '=', assetId], ['company_id', '=', companyId]]],
            kwargs: { fields: ['id'], limit: 1, context: odooCtx(companyId) },
        });

        if (!check || check.length === 0) {
            return res.status(403).json({
                status: 'error',
                error:  'Accès refusé ou immobilisation introuvable.',
            });
        }

        console.log(`✏️ [update] Asset: ${assetId}`);

        await odooExecuteKw({
            uid:    ADMIN_UID_INT,
            model:  ASSET_MODEL,
            method: 'write',
            args:   [[assetId], updates],
            kwargs: { context: odooCtx(companyId) },
        });

        console.log('✅ [update] OK');

        res.json({ status: 'success', message: 'Immobilisation mise à jour.' });

    } catch (error) {
        return errResp(res, 'Erreur mise à jour immobilisation', error.message);
    }
};

// =============================================================================
// METTRE AU REBUT
// DELETE /api/accounting/immobilisations/:id
// =============================================================================

exports.dispose = async (req, res) => {
    try {
        const assetId     = parseInt(req.params.id);
        const companyId   = req.validatedCompanyId;
        const { disposal_date } = req.body;

        if (isNaN(assetId)) {
            return res.status(400).json({ status: 'error', error: 'ID invalide' });
        }

        // Vérification d'appartenance
        const check = await odooExecuteKw({
            uid:    ADMIN_UID_INT,
            model:  ASSET_MODEL,
            method: 'search_read',
            args:   [[['id', '=', assetId], ['company_id', '=', companyId]]],
            kwargs: { fields: ['id'], limit: 1, context: odooCtx(companyId) },
        });

        if (!check || check.length === 0) {
            return res.status(403).json({
                status: 'error',
                error:  'Accès refusé ou immobilisation introuvable.',
            });
        }

        console.log(`🗑️ [dispose] Asset: ${assetId}`);

        await odooExecuteKw({
            uid:    ADMIN_UID_INT,
            model:  ASSET_MODEL,
            method: 'write',
            args:   [[assetId], {
                state:      'close',
                date_close: disposal_date || new Date().toISOString().split('T')[0],
            }],
            kwargs: { context: odooCtx(companyId) },
        });

        console.log('✅ [dispose] OK');

        res.json({ status: 'success', message: 'Immobilisation clôturée.' });

    } catch (error) {
        return errResp(res, 'Erreur clôture immobilisation', error.message);
    }
};

// =============================================================================
// RAPPORTS (Structures retournées — logique à compléter)
// =============================================================================

exports.getTableauImmobilisations = async (req, res) => {
    res.json({
        status: 'success',
        data: {
            headers: ['Catégorie', 'Valeur brute début', 'Acquisitions', 'Cessions', 'Valeur brute fin'],
            rows:    [],
            totaux:  { valeur_brute_debut: 0, acquisitions: 0, cessions: 0, valeur_brute_fin: 0 },
        },
    });
};

exports.getTableauAmortissements = async (req, res) => {
    res.json({
        status: 'success',
        data: {
            headers: ['Catégorie', 'Amort. cumulés début', 'Dotations exercice', 'Amort. cumulés fin'],
            rows:    [],
            totaux:  {},
        },
    });
};

exports.getTableauProvisions = async (req, res) => {
    res.json({
        status: 'success',
        data: {
            headers: ['Catégorie', 'Provisions début', 'Dotations', 'Reprises', 'Provisions fin'],
            rows:    [],
            totaux:  {},
        },
    });
};

exports.getEtatRapprochement = async (req, res) => {
    res.json({
        status: 'success',
        data: {
            comptabilite: { total: 0, items: [] },
            inventaire:   { total: 0, items: [] },
            ecarts:       [],
        },
    });
};
