class DeterministicRiskEngine:
    BASE_SEVERITY = {
        "INFO": 0.0,
        "LOW": 2.5,
        "MEDIUM": 5.0,
        "HIGH": 7.5,
        "CRITICAL": 9.5
    }

    CONFIDENCE_WEIGHTS = {
        "OBSERVED": 1.0,
        "VERIFIED": 1.0,
        "INFERRED": 0.7,
        "HEURISTIC": 0.5,
        "RECOMMENDED_FOR_MANUAL_REVIEW": 0.6,
        "CONFIRMED_FINDING": 1.0
    }

    @classmethod
    def calculate(cls, severity: str, classification: str, has_evidence: bool = True) -> float:
        base = cls.BASE_SEVERITY.get(severity.upper(), 0.0)
        mult = cls.CONFIDENCE_WEIGHTS.get(classification.upper(), 0.5)
        score = base * mult
        if has_evidence and score > 0:
            score = min(10.0, score + 0.5)
        return round(score, 2)
