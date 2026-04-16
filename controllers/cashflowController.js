// =============================================================================
// FICHIER : controllers/cashflowController.js
// Description : Génération du rapport de flux de trésorerie SYSCOHADA SMT.
// Version : V2 — Corrections appliquées
//   ✅ ADMIN_UID converti en entier (parseInt)
//   ✅ 'sort' remplacé par 'order' (paramètre correct odooExecuteKw)
//   ✅ Image parasite supprimée
//   ✅ Vérification ADMIN_UID via ADMIN_UID_INT (cohérence avec les autres controllers)
// =============================================================================

const { odooExecuteKw, ADMIN_UID_INT } = require('../services/odooService');

exports.getMonthlyCashflowSMT = async (req, res) => {
    try {
        const { analyticId } = req.params;

        // ✅ Utilise ADMIN_UID_INT (déjà parsé en entier dans odooService.js)
        if (!ADMIN_UID_INT || isNaN(ADMIN_UID_INT)) {
            return res.status(500).json({
                success: false,
                error: 'Configuration manquante: ODOO_ADMIN_UID invalide.'
            });
        }

        // 1. Période : 12 derniers mois
        const dateLimit = new Date();
        dateLimit.setFullYear(dateLimit.getFullYear() - 1);
        const dateString = dateLimit.toISOString().split('T')[0];

        // 2. Requête Odoo — Comptes de trésorerie (Classe 5) avec filtre analytique
        const moves = await odooExecuteKw({
            uid:    ADMIN_UID_INT,
            model:  'account.move.line',
            method: 'search_read',
            args: [[
                ['analytic_distribution', 'in', [analyticId.toString()]],
                ['account_id.code',       '=like', '5%'],
                ['date',                  '>=',    dateString],
                ['parent_state',          '=',     'posted'],
            ]],
            kwargs: {
                fields: ['date', 'debit', 'credit', 'name'],
                order:  'date asc', // ✅ 'order' et non 'sort'
            }
        });

        // 3. Agrégation par mois (SYSCOHADA SMT)
        const monthlyData = {};

        moves.forEach(move => {
            const monthKey = move.date.substring(0, 7); // "YYYY-MM"

            if (!monthlyData[monthKey]) {
                monthlyData[monthKey] = {
                    mois:    monthKey,
                    entrees: 0,
                    sorties: 0,
                    solde:   0,
                };
            }

            // Classe 5 : Débit = Entrée, Crédit = Sortie
            monthlyData[monthKey].entrees += move.debit  || 0;
            monthlyData[monthKey].sorties += move.credit || 0;
            monthlyData[monthKey].solde   += (move.debit || 0) - (move.credit || 0);
        });

        // 4. Trier par mois (ordre chronologique)
        const report = Object.values(monthlyData)
            .sort((a, b) => a.mois.localeCompare(b.mois));

        res.status(200).json({
            success:      true,
            entrepriseId: analyticId,
            referentiel:  'SYSCOHADA SMT (Trésorerie)',
            unite:        'XOF',
            periode:      {
                debut: dateString,
                fin:   new Date().toISOString().split('T')[0],
            },
            fluxMensuels: report,
        });

    } catch (error) {
        console.error('🚨 [Cashflow SMT Error]', error.message);
        res.status(500).json({
            success: false,
            error:   error.message,
            message: 'Erreur lors de la récupération des flux de trésorerie.',
        });
    }
};
