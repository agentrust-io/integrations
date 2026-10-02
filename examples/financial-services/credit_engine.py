#!/usr/bin/env python3
"""
Credit-decisioning domain logic for the financial-services example.

Pure, dependency-free functions plus a small set of realistic EU corporate
client fixtures. The mock MCP server (``server/mock_mcp_server.py``) imports
this module so the tool responses are computed from one source of truth, and
``tests/test_credit_engine.py`` exercises the logic without a running server.

Everything here is illustrative. The identifiers are valid in *format* (LEI
check digits per ISO 17442 / ISO 7064 MOD 97-10, German IBANs per the same
scheme) but the entities are fictional.
"""

from __future__ import annotations

from typing import Any

# Internal single-obligor concentration limit. Banks set this well below the
# CRR Art. 395 regulatory large-exposures ceiling (25% of Tier 1 capital) as a
# matter of risk appetite; the runtime enforces the internal limit and cites
# CRR Art. 395 as the framework it implements.
CONCENTRATION_LIMIT_EUR = 2_000_000

# Facilities above this amount exceed the automated workflow's delegated
# lending authority and require a human credit decision-maker under the EBA
# Guidelines on loan origination and monitoring (EBA/GL/2020/06).
DELEGATED_AUTHORITY_LIMIT_EUR = 500_000


# ---------------------------------------------------------------------------
# Client fixtures. Keyed by the bank's internal customer id.
# ---------------------------------------------------------------------------

CLIENTS: dict[str, dict[str, Any]] = {
    # Scenario A - clean SME, well within limits, performing.
    "DE-CORP-2024-00847": {
        "legal_name": "Rheintal Präzisionstechnik GmbH",
        "lei": "529900RHEINTAL000140",
        "creditreform_id": "20401234",
        "nace_code": "C25.62",
        "nace_label": "Machining",
        "iban": "DE89370400440532013000",
        "country": "DE",
        "ubos": [
            {"name": "Klara Hoffmann", "role": "Managing shareholder (62%)"},
            {"name": "Rheintal Beteiligungs GmbH", "role": "Holding (38%)"},
        ],
        "financials": {
            "fiscal_year": 2024,
            "total_assets_eur": 12_400_000,
            "total_equity_eur": 4_960_000,
            "total_liabilities_eur": 7_440_000,
            "revenue_eur": 18_900_000,
            "ebitda_eur": 2_460_000,
            "net_debt_eur": 3_100_000,
            "auditor_opinion": "unqualified",
        },
        "bureau_index": 178,          # Creditreform Bonitätsindex (100 best..600)
        "existing_group_exposure_eur": 900_000,
        "sanctions_hit": False,
    },
    # Scenario B - strong obligor but the new facility breaches the internal
    # concentration limit and exceeds delegated authority.
    "DE-CORP-2024-01120": {
        "legal_name": "Nordwind Logistik AG",
        "lei": "391200NORDWIND000113",
        "creditreform_id": "29004567",
        "nace_code": "H52.29",
        "nace_label": "Other transportation support activities",
        "iban": "DE58500700100923456789",
        "country": "DE",
        "ubos": [
            {"name": "Nordwind Holding SE", "role": "Parent (100%)"},
        ],
        "financials": {
            "fiscal_year": 2024,
            "total_assets_eur": 47_800_000,
            "total_equity_eur": 15_300_000,
            "total_liabilities_eur": 32_500_000,
            "revenue_eur": 61_200_000,
            "ebitda_eur": 7_950_000,
            "net_debt_eur": 21_400_000,
            "auditor_opinion": "unqualified",
        },
        "bureau_index": 205,
        "existing_group_exposure_eur": 1_450_000,
        "sanctions_hit": False,
    },
    # Scenario C - a beneficial owner matches a sanctions / PEP list.
    "AE-CORP-2024-00311": {
        "legal_name": "Meridian Trading DMCC",
        "lei": "529900MERIDIAN000175",
        "creditreform_id": None,
        "nace_code": "G46.90",
        "nace_label": "Non-specialised wholesale trade",
        "iban": None,
        "country": "AE",
        "ubos": [
            {"name": "Dmitri V. Aslanov", "role": "Beneficial owner (55%)"},
            {"name": "Meridian Holdings Ltd", "role": "Holding (45%)"},
        ],
        "financials": {
            "fiscal_year": 2023,
            "total_assets_eur": 3_100_000,
            "total_equity_eur": 420_000,
            "total_liabilities_eur": 2_680_000,
            "revenue_eur": 9_400_000,
            "ebitda_eur": 210_000,
            "net_debt_eur": 2_260_000,
            "auditor_opinion": "not_available",
        },
        "bureau_index": None,
        "existing_group_exposure_eur": 0,
        "sanctions_hit": True,
    },
}

DEFAULT_CLIENT = "DE-CORP-2024-00847"

# Internal rating masterscale: (upper bound of Creditreform index, grade, PD).
_RATING_BANDS = [
    (150, "1b", 0.0018),
    (200, "2b", 0.0061),
    (250, "3b", 0.0140),
    (300, "4b", 0.0325),
    (350, "5b", 0.0710),
    (600, "6b", 0.1600),
]


def _client(client_id: str) -> dict[str, Any]:
    return CLIENTS.get(client_id, CLIENTS[DEFAULT_CLIENT])


def read_financials(client_id: str) -> dict[str, Any]:
    """Return the latest filed financials plus derived ratios."""
    c = _client(client_id)
    f = c["financials"]
    equity_ratio = round(f["total_equity_eur"] / f["total_assets_eur"], 3)
    net_debt_to_ebitda = (
        round(f["net_debt_eur"] / f["ebitda_eur"], 2) if f["ebitda_eur"] else None
    )
    ebitda_margin = round(f["ebitda_eur"] / f["revenue_eur"], 3) if f["revenue_eur"] else None
    return {
        "client_id": client_id,
        "legal_name": c["legal_name"],
        "lei": c["lei"],
        "nace_code": c["nace_code"],
        "nace_label": c["nace_label"],
        "document_type": "annual_financial_statements",
        "fiscal_year": f["fiscal_year"],
        "total_assets_eur": f["total_assets_eur"],
        "total_equity_eur": f["total_equity_eur"],
        "total_liabilities_eur": f["total_liabilities_eur"],
        "revenue_eur": f["revenue_eur"],
        "ebitda_eur": f["ebitda_eur"],
        "net_debt_eur": f["net_debt_eur"],
        "equity_ratio": equity_ratio,
        "ebitda_margin": ebitda_margin,
        "net_debt_to_ebitda": net_debt_to_ebitda,
        "auditor_opinion": f["auditor_opinion"],
        "status": "retrieved",
    }


def screen_sanctions(client_id: str) -> dict[str, Any]:
    """Screen the entity and its beneficial owners (CDD / AML)."""
    c = _client(client_id)
    lists = [
        "EU Consolidated Financial Sanctions (CFSP)",
        "UN Security Council Consolidated List",
        "PEP",
    ]
    matches: list[dict[str, Any]] = []
    if c["sanctions_hit"]:
        matches.append({
            "matched_entity": c["ubos"][0]["name"],
            "match_type": "beneficial_owner",
            "list": "EU Consolidated Financial Sanctions (CFSP)",
            "score": 0.94,
        })
    return {
        "client_id": client_id,
        "legal_name": c["legal_name"],
        "lei": c["lei"],
        "lists_checked": lists,
        "entities_screened": [c["legal_name"]] + [u["name"] for u in c["ubos"]],
        "matches": matches,
        "cdd_status": "hit" if matches else "clear",
        "status": "completed",
    }


def bureau_report(client_id: str, bureau: str = "creditreform") -> dict[str, Any]:
    """Return a commercial credit-bureau report.

    Uses the Creditreform Bonitätsindex scale (100 best, 600 = hard negative),
    not a US FICO-style score.
    """
    c = _client(client_id)
    index = c["bureau_index"]
    return {
        "client_id": client_id,
        "bureau": bureau,
        "creditreform_id": c["creditreform_id"],
        "bonitaetsindex": index,
        "scale": "100-600 (100 = excellent, 600 = hard negative)",
        "assessment": _bureau_band(index),
        "status": "retrieved" if index is not None else "no_file",
    }


def _bureau_band(index: int | None) -> str:
    if index is None:
        return "no_commercial_credit_file"
    if index <= 149:
        return "excellent"
    if index <= 199:
        return "very_good"
    if index <= 249:
        return "good"
    if index <= 299:
        return "medium"
    if index <= 349:
        return "weak"
    return "very_weak"


def aggregate_exposure(client_id: str, proposed_facility_eur: int) -> dict[str, Any]:
    """Aggregate existing group exposure with the proposed facility and test it
    against the internal single-obligor concentration limit."""
    c = _client(client_id)
    existing = c["existing_group_exposure_eur"]
    aggregate = existing + proposed_facility_eur
    utilisation = round(aggregate / CONCENTRATION_LIMIT_EUR, 3)
    return {
        "client_id": client_id,
        "existing_group_exposure_eur": existing,
        "proposed_facility_eur": proposed_facility_eur,
        "aggregate_exposure_eur": aggregate,
        "concentration_limit_eur": CONCENTRATION_LIMIT_EUR,
        "limit_utilisation": utilisation,
        "breaches_concentration_limit": aggregate > CONCENTRATION_LIMIT_EUR,
        "framework": "CRR Art. 395 (large exposures); internal risk-appetite limit",
        "status": "completed",
    }


def run_risk_model(client_id: str, proposed_facility_eur: int) -> dict[str, Any]:
    """Compute PD / LGD / EAD, the internal rating grade and the IFRS 9 stage."""
    c = _client(client_id)
    index = c["bureau_index"]
    grade, pd = _rating_from_index(index)
    f = c["financials"]
    # A simple, legible IFRS 9 staging rule for the demo: unaudited or very
    # weak files are treated as under-performing / credit-impaired.
    if f["auditor_opinion"] == "not_available" or (index is not None and index > 349):
        ifrs9_stage = 3
    elif index is not None and index > 249:
        ifrs9_stage = 2
    else:
        ifrs9_stage = 1
    lgd = 0.35  # senior secured corporate, illustrative
    ead = proposed_facility_eur
    expected_loss = round(pd * lgd * ead) if pd is not None else None
    return {
        "client_id": client_id,
        "internal_rating": grade,
        "pd_1y": pd,
        "lgd": lgd,
        "ead_eur": ead,
        "expected_loss_eur": expected_loss,
        "ifrs9_stage": ifrs9_stage,
        "model_id": "corp-pd-lgd-v2.3",
        "status": "completed",
    }


def _rating_from_index(index: int | None) -> tuple[str | None, float | None]:
    if index is None:
        return "unrated", None
    for upper, grade, pd in _RATING_BANDS:
        if index <= upper:
            return grade, pd
    return "6b", 0.16
