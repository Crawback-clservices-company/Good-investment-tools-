"""Heuristic risk engine for smart-contract source code and whitepaper text."""
import re

RULES = [
    ("owner_can_mint", r"function\s+mint\s*\([^)]*\)[^{]*\b(onlyOwner|owner)\b", 30, "Owner can mint unlimited tokens"),
    ("blacklist", r"\b(blacklist|isBlacklisted|_blocked)\b", 20, "Blacklist can block holders from selling (honeypot pattern)"),
    ("selfdestruct", r"\bselfdestruct\s*\(", 25, "Contract can be destroyed"),
    ("withdraw_all", r"function\s+(withdrawAll|drain|rugPull)\s*\(", 35, "Owner can withdraw all funds"),
    ("mutable_fee", r"function\s+set(Tax|Fee)\w*\s*\(", 15, "Fees can be changed after launch"),
    ("delegatecall", r"\bdelegatecall\s*\(", 15, "Arbitrary delegatecall"),
    ("pausable_transfer", r"function\s+(pause|setTradingEnabled)\s*\(", 10, "Owner can freeze trading"),
    ("tx_origin", r"\btx\.origin\b", 10, "tx.origin used for authorization"),
    ("guaranteed_returns", r"guaranteed\s+(returns?|profits?)|risk[- ]free|garantizad[oa]s?|sin\s+riesgo", 30, "Promises guaranteed or risk-free returns"),
    ("ponzi_referral", r"referral\s+(bonus|reward)|multi[- ]level|referidos?|pir[aá]mide", 20, "Referral/pyramid style incentives"),
    ("anonymous_team", r"anonymous\s+team|equipo\s+an[oó]nimo", 15, "Anonymous team"),
]
POSITIVE = [
    ("audit", r"\baudit(ed|oria)?\b", -10, "Mentions an audit"),
    ("renounced", r"renounceOwnership", -5, "Ownership can be renounced"),
]


def analyze(source_code="", whitepaper=""):
    text = f"{source_code}\n{whitepaper}"
    findings, score = [], 0
    for rid, pat, pts, msg in RULES + POSITIVE:
        if re.search(pat, text, re.I):
            findings.append({"id": rid, "points": pts, "message": msg})
            score += pts
    score = max(0, min(100, score))
    level = "high" if score >= 50 else "medium" if score >= 20 else "low"
    return {
        "risk_score": score,
        "risk_level": level,
        "verdict": "likely_fraudulent" if score >= 70 else "suspicious" if score >= 40 else "no_major_red_flags",
        "findings": findings,
    }
