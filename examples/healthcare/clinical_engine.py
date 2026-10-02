#!/usr/bin/env python3
"""
Clinical domain logic for the healthcare example.

Pure, dependency-free functions plus one coherent patient fixture. The mock EHR
server serves from this module, and tests/test_clinical_engine.py exercises the
logic without a running server, so the record, the differential and the
drug-interaction check all agree on the same patient.

Everything here is illustrative and fictional. Diagnoses carry ICD-10 codes,
medications carry dosing, and the differential is consistent with the record.
"""

from __future__ import annotations

from typing import Any

# One worked patient: a 54-year-old with type 2 diabetes and hypertension whose
# glycaemic control has drifted (HbA1c 8.1%).
PATIENT: dict[str, Any] = {
    "patient_id": "P-2024-008471",
    "age": 54,
    "sex": "female",
    "active_diagnoses": [
        {"icd10": "E11.9", "label": "Type 2 diabetes mellitus without complications"},
        {"icd10": "I10", "label": "Essential (primary) hypertension"},
        {"icd10": "E78.5", "label": "Hyperlipidaemia, unspecified"},
    ],
    "current_medications": [
        {"name": "metformin", "dose": "500 mg", "frequency": "twice daily"},
        {"name": "lisinopril", "dose": "10 mg", "frequency": "once daily"},
        {"name": "atorvastatin", "dose": "20 mg", "frequency": "once daily"},
    ],
    "allergies": [
        {"substance": "penicillin", "reaction": "urticaria"},
        {"substance": "sulfonamides", "reaction": "rash"},
    ],
    "labs": {
        "hba1c_percent": 8.1,
        "fasting_glucose_mmol": 9.2,
        "egfr_ml_min": 78,
        "ldl_mmol": 2.9,
        "blood_pressure_mmhg": "148/92",
        "bmi": 31.4,
    },
    "last_visit": "2026-05-28",
}

# Small illustrative interaction knowledge base.
# Drug classes the patient's allergies contraindicate.
_ALLERGY_CONTRAINDICATIONS = {
    "sulfonamides": ["co-trimoxazole", "sulfamethoxazole", "sulfasalazine"],
    "penicillin": ["amoxicillin", "ampicillin", "co-amoxiclav", "piperacillin"],
}
# Pairwise drug-drug interactions with the patient's current medications.
_DRUG_DRUG = {
    ("lisinopril", "spironolactone"): ("moderate", "additive hyperkalaemia risk"),
    ("lisinopril", "potassium chloride"): ("severe", "hyperkalaemia risk"),
    ("atorvastatin", "clarithromycin"): ("severe", "increased myopathy/rhabdomyolysis risk"),
}


def patient_record(patient_id: str, record_type: str = "full") -> dict[str, Any]:
    """Return the patient record, or the requested section of it."""
    p = PATIENT
    full = {
        "patient_id": patient_id or p["patient_id"],
        "age": p["age"],
        "sex": p["sex"],
        "active_diagnoses": p["active_diagnoses"],
        "current_medications": p["current_medications"],
        "allergies": p["allergies"],
        "labs": p["labs"],
        "last_visit": p["last_visit"],
    }
    sections = {
        "demographics": {"patient_id": full["patient_id"], "age": p["age"], "sex": p["sex"]},
        "diagnoses": {"patient_id": full["patient_id"], "active_diagnoses": p["active_diagnoses"]},
        "medications": {"patient_id": full["patient_id"], "current_medications": p["current_medications"]},
        "labs": {"patient_id": full["patient_id"], "labs": p["labs"]},
        "vitals": {"patient_id": full["patient_id"], "blood_pressure_mmhg": p["labs"]["blood_pressure_mmhg"], "bmi": p["labs"]["bmi"]},
    }
    out = sections.get(record_type, full)
    out["record_type"] = record_type
    out["status"] = "retrieved"
    return out


def clinical_decision_support(patient_id: str, presenting_symptoms: list[str] | None = None) -> dict[str, Any]:
    """Differential and recommendations consistent with the patient record."""
    return {
        "patient_id": patient_id or PATIENT["patient_id"],
        "presenting_symptoms": presenting_symptoms or ["fatigue", "polyuria", "polydipsia"],
        "differential": [
            {"condition": "Type 2 diabetes mellitus, suboptimal glycaemic control",
             "icd10": "E11.65", "confidence": 0.93},
            {"condition": "Metabolic syndrome", "icd10": "E88.81", "confidence": 0.68},
        ],
        "assessment": "HbA1c 8.1% is above the individualised target; first-line metformin "
                      "alone is insufficient. Consider adding a second-line agent.",
        "recommended_actions": [
            "Intensify glycaemic control (add second-line agent)",
            "Reinforce lifestyle measures",
            "Recheck HbA1c in 3 months",
        ],
        "status": "completed",
    }


def drug_interaction_check(patient_id: str, proposed_medications: list[str]) -> dict[str, Any]:
    """Check proposed medications against current meds and documented allergies."""
    proposed = [m.strip().lower() for m in (proposed_medications or [])]
    allergies = [a["substance"] for a in PATIENT["allergies"]]
    current = [m["name"] for m in PATIENT["current_medications"]]

    contraindications: list[dict[str, Any]] = []
    for allergy in allergies:
        for drug in _ALLERGY_CONTRAINDICATIONS.get(allergy, []):
            if drug in proposed:
                contraindications.append({
                    "proposed": drug,
                    "type": "allergy",
                    "detail": f"contraindicated: documented {allergy} allergy",
                    "severity": "severe",
                })

    interactions: list[dict[str, Any]] = []
    for cur in current:
        for prop in proposed:
            hit = _DRUG_DRUG.get((cur, prop)) or _DRUG_DRUG.get((prop, cur))
            if hit:
                severity, detail = hit
                interactions.append({
                    "current": cur, "proposed": prop,
                    "type": "drug-drug", "detail": detail, "severity": severity,
                })

    flags = contraindications + interactions
    has_severe = any(f["severity"] == "severe" for f in flags)
    return {
        "patient_id": patient_id or PATIENT["patient_id"],
        "proposed_medications": proposed,
        "contraindications": contraindications,
        "interactions": interactions,
        "highest_severity": _highest_severity(flags),
        "has_severe_contraindication": has_severe,
        "status": "completed",
    }


def _highest_severity(flags: list[dict[str, Any]]) -> str:
    order = {"none": 0, "moderate": 1, "severe": 2}
    best = "none"
    for f in flags:
        if order.get(f["severity"], 0) > order[best]:
            best = f["severity"]
    return best
