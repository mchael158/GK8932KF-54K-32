//! Motor de correlação (integridade + pacote + latência) — Fase 5.

use sentinel_inventory::InventoryDiff;

#[derive(Debug, Clone)]
pub struct AnomalyReport {
    pub summary: String,
    pub recommendation: String,
}

pub fn summarize_inventory_diff(diff: &InventoryDiff) -> AnomalyReport {
    let mut parts = Vec::new();
    if !diff.packages_changed.is_empty() {
        parts.push(format!("{} pacote(s) atualizado(s)", diff.packages_changed.len()));
    }
    if !diff.executables_hash_changed.is_empty() {
        parts.push(format!(
            "{} executável(is) com hash alterado",
            diff.executables_hash_changed.len()
        ));
    }
    if !diff.orphans_added.is_empty() {
        parts.push(format!("{} órfão(s) novo(s)", diff.orphans_added.len()));
    }
    let summary = if parts.is_empty() {
        "Nenhuma alteração relevante".into()
    } else {
        parts.join("; ")
    };
    let recommendation = if !diff.executables_hash_changed.is_empty() {
        "Investigue executáveis com hash alterado e correlacione com pacotes e latência.".into()
    } else {
        "Revise o diff completo se a alteração for inesperada.".into()
    };
    AnomalyReport {
        summary,
        recommendation,
    }
}
