#!/usr/bin/env python3
"""
People-directory domain logic for the multi-tenant-saas example.

PeopleGraph is a fictional HR / people-analytics SaaS. This module holds the
employee fixtures and the pure functions the mock MCP server serves, so the
server, the tests and the agent agree on one source of truth. No dependencies.

The data is deliberately free of phone numbers, e-mail addresses and other
patterns a response scanner would flag, so the demo turns purely on the
per-tenant policy difference rather than on incidental PII detections.
"""

from __future__ import annotations

from typing import Any

# Regions that count as inside the EEA for data-residency purposes.
EEA_REGIONS = ["eu-central-1", "eu-west-1", "eu-north-1", "eu-west-3"]

EMPLOYEES: dict[str, dict[str, Any]] = {
    "EMP-DE-4821": {
        "name": "Katharina Vogel",
        "role": "Senior Data Engineer",
        "department": "Engineering",
        "location": "Munich, DE",
        "region": "eu-central-1",
        "manager_id": "EMP-DE-3300",
        "comp_band": "L5",
        "base_salary_eur": 96_000,
        "tenure_years": 4.2,
    },
    "EMP-DE-3300": {
        "name": "Stefan Brandt",
        "role": "Engineering Manager",
        "department": "Engineering",
        "location": "Munich, DE",
        "region": "eu-central-1",
        "manager_id": None,
        "comp_band": "M2",
        "base_salary_eur": 128_000,
        "tenure_years": 7.1,
    },
    "EMP-US-1099": {
        "name": "Marcus Bell",
        "role": "Product Manager",
        "department": "Product",
        "location": "Columbus, US",
        "region": "us-east-1",
        "manager_id": "EMP-US-1000",
        "comp_band": "L5",
        "base_salary_usd": 132_000,
        "tenure_years": 3.4,
    },
}

DEFAULT_EMPLOYEE = "EMP-DE-4821"


def headcount_analytics(metric: str = "attrition", period: str = "2026-Q2") -> dict[str, Any]:
    """Aggregate, non-identifying people metrics."""
    by_department: dict[str, int] = {}
    for emp in EMPLOYEES.values():
        by_department[emp["department"]] = by_department.get(emp["department"], 0) + 1
    return {
        "metric": metric,
        "period": period,
        "headcount_total": len(EMPLOYEES),
        "headcount_by_department": by_department,
        "attrition_rate": 0.081,
        "voluntary_share": 0.63,
        "status": "completed",
    }


def employee_record_lookup(employee_id: str, include_special_category: bool = False) -> dict[str, Any]:
    """Return a single employee record.

    Special-category data (GDPR Art. 9) is never emitted here; access to it is a
    request attribute the policy decides on, so the sensitive fields do not flow
    at all when a tenant forbids them.
    """
    emp = EMPLOYEES.get(employee_id, EMPLOYEES[DEFAULT_EMPLOYEE])
    record = {
        "employee_id": employee_id,
        "name": emp["name"],
        "role": emp["role"],
        "department": emp["department"],
        "location": emp["location"],
        "region": emp["region"],
        "manager_id": emp["manager_id"],
        "comp_band": emp["comp_band"],
        "tenure_years": emp["tenure_years"],
    }
    if "base_salary_eur" in emp:
        record["base_salary_eur"] = emp["base_salary_eur"]
    if "base_salary_usd" in emp:
        record["base_salary_usd"] = emp["base_salary_usd"]
    record["special_category_included"] = bool(include_special_category)
    record["status"] = "retrieved"
    return record


def data_export(scope: str, destination_region: str) -> dict[str, Any]:
    """Export a set of employee records to a destination region."""
    matched = [e for e in EMPLOYEES.values() if scope in ("all", e["department"].lower())]
    return {
        "scope": scope,
        "destination_region": destination_region,
        "destination_in_eea": destination_region in EEA_REGIONS,
        "records_exported": len(matched) or len(EMPLOYEES),
        "export_id": "EXP-2026-00917",
        "status": "exported",
    }


def config_update(key: str, value: str) -> dict[str, Any]:
    return {
        "key": key,
        "value": value,
        "previous_value": "30",
        "status": "updated",
    }
