"""AI-Assisted Container Security Auditor for Porygon.

Analyzes container process-execution timelines, parent-child lineages,
vulnerability exposure, and Porygon's statistical drift score against
an LLM (Google Gemini, OpenAI, or Anthropic) via the operator's private API key.
"""
from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from porygon_api.schemas import AiAuditOut, AiFlaggedCommand

logger = logging.getLogger("porygon.ai")

SYSTEM_INSTRUCTION = """You are Porygon's expert Linux container runtime security AI analyst.
Your job is to examine kernel eBPF process execution traces (execve), container configuration,
and existing deterministic/statistical security signals from Porygon to detect suspicious
behavior, evasion techniques, living-off-the-land attacks, or compromise.

You must output STRICT, VALID JSON conforming to the requested schema. Do not include markdown
fences or commentary outside the JSON object.
"""

DEFAULT_MODELS: dict[str, str] = {
    "gemini": "gemini-2.0-flash",
    "openai": "gpt-4o-mini",
    "anthropic": "claude-3-5-haiku-20241022",
}


def build_audit_prompt(
    container_info: dict[str, Any],
    events: list[dict[str, Any]],
    porygon_drift_score: float | None,
    matched_rules: list[str],
    cves: list[dict[str, Any]],
) -> str:
    """Build a structured prompt summarizing the container's runtime state."""
    prompt_data = {
        "container": {
            "id": container_info.get("container_id"),
            "name": container_info.get("container_name"),
            "image_ref": container_info.get("image_ref"),
            "image_digest": container_info.get("image_digest"),
            "ports": container_info.get("ports", []),
        },
        "porygon_signals": {
            "jensen_shannon_drift_score": porygon_drift_score,
            "deterministic_rules_triggered": matched_rules,
        },
        "known_image_cves": cves[:15],
        "recent_process_executions": [
            {
                "occurred_at": e.get("occurred_at"),
                "process": e.get("process_name"),
                "executable": e.get("executable"),
                "command_line": e.get("command_line"),
                "user_uid": e.get("user_uid"),
                "parent_name": e.get("parent_name"),
                "parent_cmd": e.get("parent_command_line"),
            }
            for e in events
        ],
    }

    instructions = """
Analyze the above container telemetry. Evaluate:
1. Are there living-off-the-land binaries, unseen shells, suspicious downloaders, credential access, or privilege changes?
2. Does the sequence of processes suggest recon, staging, defense evasion, or exploitation?
3. Compare with Porygon's deterministic rules: did rules catch it, or does semantic AI analysis reveal subtle nuance the rules missed?

Respond with a single JSON object matching this schema exactly:
{
  "ai_risk_score": <float between 0.00 and 1.00, where 0.0 is completely normal and 1.0 is confirmed malicious>,
  "threat_level": <"clean" | "low" | "medium" | "high" | "critical">,
  "confidence": <float between 0.00 and 1.00>,
  "summary": <concise 1-2 sentence executive summary of findings>,
  "semantic_analysis": <paragraph explaining what the executed processes are doing and the overall intent>,
  "flagged_commands": [
    {
      "command": <string of specific command line>,
      "executable": <string path to executable>,
      "user_uid": <integer UID>,
      "occurred_at": <string or null>,
      "reason": <why this command is concerning or suspicious>,
      "severity": <"low" | "medium" | "high" | "critical">
    }
  ],
  "containment_suggestions": [
    <string with specific actionable recommendation, e.g. "Pause container", "Inspect /tmp", "Block egress IP">
  ],
  "rule_gap_analysis": <how this assessment complements or goes beyond Porygon's deterministic rules>
}
"""
    return f"{SYSTEM_INSTRUCTION}\n\nCONTAINER TELEMETRY:\n{json.dumps(prompt_data, indent=2)}\n\n{instructions}"


def _extract_json_from_text(raw: str) -> dict[str, Any]:
    """Strip markdown code blocks or wrapping text and parse JSON."""
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    
    # Try finding the first { and last }
    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        cleaned = cleaned[first_brace : last_brace + 1]

    return json.loads(cleaned)


def _gemini_headers(api_key: str) -> dict[str, str]:
    """Carry the Gemini key in a header rather than the URL.

    Google accepts the key as either a `key=` query parameter or the
    `x-goog-api-key` header. A URL is the part of a request that lands in proxy
    access logs, error messages that echo the target, and exception reprs; a
    header generally is not. The other two providers already use headers.
    """
    return {"Content-Type": "application/json", "x-goog-api-key": api_key}


def _list_gemini_models(api_key: str) -> list[str]:
    """Query Google API to discover available models that support generateContent."""
    try:
        url = "https://generativelanguage.googleapis.com/v1beta/models"
        req = urllib.request.Request(url, headers={"x-goog-api-key": api_key})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        available = []
        for m in data.get("models", []):
            methods = m.get("supportedGenerationMethods", [])
            if "generateContent" in methods:
                name = m.get("name", "").replace("models/", "")
                if name:
                    available.append(name)
        return available
    except Exception as exc:
        logger.warning("Could not query Gemini ListModels: %s", exc)
        return []


def _call_gemini(api_key: str, model: str, prompt: str) -> dict[str, Any]:
    clean_model = model.replace("models/", "").strip()
    candidates = [clean_model]
    for fallback in ["gemini-2.0-flash", "gemini-1.5-flash-latest", "gemini-1.5-flash-001", "gemini-2.0-flash-exp", "gemini-pro"]:
        if fallback not in candidates:
            candidates.append(fallback)

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
        },
    }

    last_error: Exception | None = None
    for candidate in candidates:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{candidate}:generateContent"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=_gemini_headers(api_key),
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            content_text = data["candidates"][0]["content"]["parts"][0]["text"]
            return _extract_json_from_text(content_text)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                last_error = exc
                continue
            raise

    # Dynamic lookup via ListModels if candidate list 404s
    available = _list_gemini_models(api_key)
    if available:
        preferred = next((m for m in available if "flash" in m), available[0])
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{preferred}:generateContent"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=_gemini_headers(api_key),
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        content_text = data["candidates"][0]["content"]["parts"][0]["text"]
        return _extract_json_from_text(content_text)

    if last_error:
        raise last_error
    raise ValueError("Could not find a supported Gemini model for generateContent.")


def _call_openai(api_key: str, model: str, prompt: str) -> dict[str, Any]:
    url = "https://api.openai.com/v1/chat/completions"
    payload = {
        "model": model,
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": SYSTEM_INSTRUCTION},
            {"role": "user", "content": prompt},
        ],
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    content_text = data["choices"][0]["message"]["content"]
    return _extract_json_from_text(content_text)


def _call_anthropic(api_key: str, model: str, prompt: str) -> dict[str, Any]:
    url = "https://api.anthropic.com/v1/messages"
    payload = {
        "model": model,
        "max_tokens": 1500,
        "system": SYSTEM_INSTRUCTION + "\nReturn strictly a valid JSON object matching the requested schema.",
        "messages": [{"role": "user", "content": prompt}],
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    content_text = data["content"][0]["text"]
    return _extract_json_from_text(content_text)


def perform_container_audit(
    container_info: dict[str, Any],
    events: list[dict[str, Any]],
    porygon_drift_score: float | None,
    matched_rules: list[str],
    cves: list[dict[str, Any]],
    provider: str,
    api_key: str,
    model: str | None = None,
) -> AiAuditOut:
    """Dispatches container telemetry to the selected AI provider and parses the result."""
    provider_clean = (provider or "gemini").lower().strip()
    selected_model = model or DEFAULT_MODELS.get(provider_clean, "gemini-1.5-flash")

    prompt = build_audit_prompt(
        container_info=container_info,
        events=events,
        porygon_drift_score=porygon_drift_score,
        matched_rules=matched_rules,
        cves=cves,
    )

    try:
        if provider_clean == "gemini":
            result = _call_gemini(api_key, selected_model, prompt)
        elif provider_clean == "openai":
            result = _call_openai(api_key, selected_model, prompt)
        elif provider_clean == "anthropic":
            result = _call_anthropic(api_key, selected_model, prompt)
        else:
            raise ValueError(f"Unsupported AI provider: {provider_clean}. Choose 'gemini', 'openai', or 'anthropic'.")
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        logger.error("AI API HTTP %s error (%s): %s", exc.code, provider_clean, err_body)
        if exc.code in (401, 403):
            raise ValueError(f"{provider_clean.capitalize()} API key was rejected (HTTP {exc.code}). Check your key.") from exc
        if exc.code == 429:
            raise ValueError(f"{provider_clean.capitalize()} rate limit exceeded or quota exhausted (HTTP 429).") from exc
        raise ValueError(f"{provider_clean.capitalize()} API error: HTTP {exc.code} - {err_body[:200]}") from exc
    except urllib.error.URLError as exc:
        logger.error("Network error reaching %s API: %s", provider_clean, exc)
        raise ValueError(f"Could not connect to {provider_clean.capitalize()} API: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse JSON response from %s: %s", provider_clean, exc)
        raise ValueError("AI provider returned invalid JSON") from exc

    # Parse and validate fields into typed schema
    risk_score = float(result.get("ai_risk_score", 0.0))
    risk_score = max(0.0, min(1.0, risk_score))

    threat_level = str(result.get("threat_level", "low")).lower()
    if threat_level not in ("clean", "low", "medium", "high", "critical"):
        threat_level = "medium" if risk_score >= 0.5 else "low"

    confidence = float(result.get("confidence", 0.85))
    confidence = max(0.0, min(1.0, confidence))

    flagged: list[AiFlaggedCommand] = []
    for f in result.get("flagged_commands", []):
        if isinstance(f, dict) and f.get("command"):
            sev = str(f.get("severity", "medium")).lower()
            if sev not in ("low", "medium", "high", "critical"):
                sev = "medium"
            flagged.append(
                AiFlaggedCommand(
                    command=str(f.get("command")),
                    executable=str(f.get("executable", "")),
                    user_uid=int(f.get("user_uid", 0)),
                    occurred_at=f.get("occurred_at"),
                    reason=str(f.get("reason", "Suspicious command")),
                    severity=sev,  # type: ignore[arg-type]
                )
            )

    suggestions = [str(s) for s in result.get("containment_suggestions", []) if s]

    return AiAuditOut(
        container_id=container_info.get("container_id", ""),
        container_name=container_info.get("container_name"),
        image_ref=container_info.get("image_ref"),
        provider=provider_clean,
        model=selected_model,
        ai_risk_score=round(risk_score, 3),
        threat_level=threat_level,  # type: ignore[arg-type]
        confidence=round(confidence, 3),
        porygon_drift_score=porygon_drift_score,
        matched_rules=matched_rules,
        summary=str(result.get("summary", "No summary provided.")),
        semantic_analysis=str(result.get("semantic_analysis", "Analysis completed.")),
        flagged_commands=flagged,
        containment_suggestions=suggestions,
        rule_gap_analysis=result.get("rule_gap_analysis"),
        audited_at=datetime.now(timezone.utc),
    )
