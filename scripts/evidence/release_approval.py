#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Shared release approval input contract."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any


SCHEMA_VERSION = "suderra.release-approval.v2"
DECISION_STATUS_VALUES = {"approved", "approved_with_residual_risk", "blocked"}
RISK_STATUS_VALUES = {"none", "accepted", "blocked"}
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _timestamp(value: Any, path: str, errors: list[str], required: bool = True) -> datetime | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.endswith("Z"):
        errors.append(f"{path}: must be an ISO-8601 UTC timestamp ending in Z")
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        errors.append(f"{path}: must be an ISO-8601 UTC timestamp")
        return None


def _string(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{path}: must be a non-empty string")


def validate_approval_payload(
    payload: Any,
    version: str,
    target: str,
    expected_source_sha: str | None = None,
    require_pass: bool = True,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["approval input must be a JSON object"]
    if payload.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"$.schema_version: must be {SCHEMA_VERSION}")
    if payload.get("version") != version:
        errors.append(f"$.version: must match {version}")
    if payload.get("target") != target:
        errors.append(f"$.target: must match {target}")
    source_sha = payload.get("source_sha")
    if source_sha is not None:
        if not isinstance(source_sha, str) or not SOURCE_SHA_RE.fullmatch(source_sha):
            errors.append("$.source_sha: must be a lowercase git commit sha")
        elif expected_source_sha is not None and source_sha != expected_source_sha:
            errors.append(f"$.source_sha: must match bound source sha {expected_source_sha}")
    elif expected_source_sha is not None:
        errors.append("$.source_sha: must be present when source binding is enforced")

    approvals = payload.get("approvals")
    if not isinstance(approvals, list):
        errors.append("$.approvals: must be a list")
        approvals = []
    if require_pass and not approvals:
        errors.append("$.approvals: must include at least one approval")
    seen_roles: set[str] = set()
    for idx, approval in enumerate(approvals):
        path = f"$.approvals[{idx}]"
        if not isinstance(approval, dict):
            errors.append(f"{path}: must be an object")
            continue
        for field in ("role", "name", "approved_at"):
            _string(approval.get(field), f"{path}.{field}", errors)
        role = approval.get("role")
        if isinstance(role, str):
            if role in seen_roles:
                errors.append(f"{path}.role: must be unique within approvals")
            seen_roles.add(role)
        _timestamp(approval.get("approved_at"), f"{path}.approved_at", errors)
        if "ticket" in approval:
            _string(approval.get("ticket"), f"{path}.ticket", errors)
    if require_pass:
        if "release-owner" not in seen_roles:
            errors.append("$.approvals: must include release-owner approval")
        if not ({"maintainer", "security-compliance"} & seen_roles):
            errors.append("$.approvals: must include maintainer or security-compliance approval")
        if len(seen_roles) < 2:
            errors.append("$.approvals: must include at least two distinct approval roles")

    decision = payload.get("release_decision")
    if not isinstance(decision, dict):
        errors.append("$.release_decision: must be an object")
        decision = {}
    status = decision.get("status")
    if status not in DECISION_STATUS_VALUES:
        errors.append("$.release_decision.status: must be approved, approved_with_residual_risk, or blocked")
    for field in ("decided_by", "decided_at", "rationale"):
        _string(decision.get(field), f"$.release_decision.{field}", errors)
    _timestamp(decision.get("decided_at"), "$.release_decision.decided_at", errors)
    if require_pass and status not in {"approved", "approved_with_residual_risk"}:
        errors.append("$.release_decision.status: must approve the release input")

    residual_risk = payload.get("residual_risk", {"status": "none", "items": []})
    if not isinstance(residual_risk, dict):
        errors.append("$.residual_risk: must be an object")
        residual_risk = {}
    risk_status = residual_risk.get("status")
    if risk_status not in RISK_STATUS_VALUES:
        errors.append("$.residual_risk.status: must be none, accepted, or blocked")
    items = residual_risk.get("items")
    if not isinstance(items, list):
        errors.append("$.residual_risk.items: must be a list")
        items = []
    for idx, item in enumerate(items):
        path = f"$.residual_risk.items[{idx}]"
        if not isinstance(item, dict):
            errors.append(f"{path}: must be an object")
            continue
        for field in ("id", "severity", "description", "mitigation", "owner", "ticket"):
            _string(item.get(field), f"{path}.{field}", errors)
    if require_pass and status == "approved":
        if risk_status != "none":
            errors.append("$.residual_risk.status: must be none for approved releases")
        if items:
            errors.append("$.residual_risk.items: must be empty for approved releases")
    if require_pass and status == "approved_with_residual_risk":
        if risk_status != "accepted":
            errors.append("$.residual_risk.status: must be accepted for residual-risk approval")
        if not items:
            errors.append("$.residual_risk.items: must list accepted residual risks")
        for field in ("accepted_by", "accepted_at", "expires_at"):
            _string(residual_risk.get(field), f"$.residual_risk.{field}", errors)
        _timestamp(residual_risk.get("accepted_at"), "$.residual_risk.accepted_at", errors)
        expires_at = _timestamp(residual_risk.get("expires_at"), "$.residual_risk.expires_at", errors)
        if expires_at is not None and expires_at <= datetime.now(timezone.utc):
            errors.append("$.residual_risk.expires_at: must be in the future")
    if require_pass and risk_status == "blocked":
        errors.append("$.residual_risk.status: must not be blocked")
    return errors
