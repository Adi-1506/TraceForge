from fastapi import APIRouter, Depends

from server.auth import current_user
from server.detection import sigma
from server.scoring import nist

router = APIRouter(prefix="/rules", tags=["rules"], dependencies=[Depends(current_user)])


@router.get("")
def list_rules():
    """The Sigma detection rules in force, with each one's level, ATT&CK tags and risk score."""
    return {
        "format": "Sigma (https://github.com/SigmaHQ/sigma-specification)",
        "risk_assessment": "NIST SP 800-30 Rev. 1: likelihood and impact (Tables G-4, H-3), level of risk (Table I-2); "
        "risk value = likelihood x impact / 100 (ISO/IEC 27005), within the Table I-3 range",
        "levels": {
            name: {"label": nist.LABELS[name], "from": lo, "to": hi, "sigma_level": nist.SIGMA_LEVEL[name]}
            for name, (lo, hi) in nist.SCALE.items()
        },
        "risk_matrix": {lik: dict(zip(nist.LEVELS, row)) for lik, row in nist.RISK_MATRIX.items()},
        "rules": [r.summary() for r in sigma.RULES],
    }
