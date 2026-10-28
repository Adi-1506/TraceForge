"""Where every rule weight comes from: OWASP Risk Rating x evidence confidence.

A finding is evidence that a particular attack may be happening. Its weight answers two
separate questions, so neither number is plucked from the air:

1. How severe is the attack this finding points to?
   Rated with the OWASP Risk Rating Methodology (the factor-based instance of the
   likelihood x impact model in NIST SP 800-30 Rev. 1). Each attack class below scores the
   8 OWASP likelihood factors and the 4 OWASP technical-impact factors, using only the
   option values OWASP defines (0-9). Likelihood = mean of the likelihood factors,
   impact = mean of the impact factors, each banded LOW (<3) / MEDIUM (<6) / HIGH, and the
   OWASP severity matrix gives Note / Low / Medium / High / Critical.

2. How sure are we that this finding means that attack (and not a benign cause)?
   The evidence confidence c in [0, 1]. These are analyst priors with a stated reason;
   `python -m server.scoring.calibrate` measures each indicator's precision on the
   labelled synthetic scenarios so the priors can be checked against data.

    weight = c x SEVERITY_POINTS[severity]

SEVERITY_POINTS equal the dashboard's score bands (25 medium, 50 high, 75 critical), so
one fully confident finding of OWASP severity S places a connection in level S on its own;
weaker evidence is discounted by c, and independent findings add up (corroboration).

Rating convention: "intrusion detection" is rated for the machine as it would be WITHOUT
TraceForge (the OS records the device in its PnP log but nobody reviews it: "logged without
review", 8), so the rating describes the exposure TraceForge is there to reduce.
"""

from dataclasses import dataclass

LIKELIHOOD_FACTORS = (
    "skill_level", "motive", "opportunity", "size",
    "ease_of_discovery", "ease_of_exploit", "awareness", "intrusion_detection",
)
IMPACT_FACTORS = ("confidentiality", "integrity", "availability", "accountability")

# The values OWASP allows for each factor; a rating outside these is rejected at import time.
ALLOWED = {
    "skill_level": {1, 3, 5, 6, 9},
    "motive": {1, 4, 9},
    "opportunity": {0, 4, 7, 9},
    "size": {2, 4, 5, 6, 9},
    "ease_of_discovery": {1, 3, 7, 9},
    "ease_of_exploit": {1, 3, 5, 9},
    "awareness": {1, 4, 6, 9},
    "intrusion_detection": {1, 3, 8, 9},
    "confidentiality": {2, 6, 7, 9},
    "integrity": {1, 3, 5, 7, 9},
    "availability": {1, 5, 7, 9},
    "accountability": {1, 7, 9},
}

# OWASP severity matrix: (likelihood level, impact level) -> overall severity.
MATRIX = {
    ("LOW", "LOW"): "Note", ("MEDIUM", "LOW"): "Low", ("HIGH", "LOW"): "Medium",
    ("LOW", "MEDIUM"): "Low", ("MEDIUM", "MEDIUM"): "Medium", ("HIGH", "MEDIUM"): "High",
    ("LOW", "HIGH"): "Medium", ("MEDIUM", "HIGH"): "High", ("HIGH", "HIGH"): "Critical",
}
SEVERITY_POINTS = {"Note": 0, "Low": 10, "Medium": 25, "High": 50, "Critical": 75}


def band(value: float) -> str:
    return "LOW" if value < 3 else "MEDIUM" if value < 6 else "HIGH"


@dataclass(frozen=True)
class AttackClass:
    key: str
    title: str
    techniques: tuple[str, ...]  # MITRE ATT&CK
    likelihood: dict
    impact: dict
    why: str

    @property
    def likelihood_score(self) -> float:
        return round(sum(self.likelihood[f] for f in LIKELIHOOD_FACTORS) / len(LIKELIHOOD_FACTORS), 3)

    @property
    def impact_score(self) -> float:
        return round(sum(self.impact[f] for f in IMPACT_FACTORS) / len(IMPACT_FACTORS), 3)

    @property
    def severity(self) -> str:
        return MATRIX[(band(self.likelihood_score), band(self.impact_score))]


ATTACKS = {
    a.key: a
    for a in [
        AttackClass(
            "keystroke_injection_device",
            "Rogue HID / keystroke-injection device (BadUSB, Rubber Ducky)",
            ("T1200", "T1059"),
            dict(skill_level=5, motive=9, opportunity=7, size=4, ease_of_discovery=7, ease_of_exploit=9, awareness=9, intrusion_detection=8),
            dict(confidentiality=7, integrity=7, availability=5, accountability=7),
            "Off-the-shelf injectors and payload libraries exist (ease of exploit: automated tools, 9; "
            "awareness: public, 9); it needs a moment of physical access (opportunity: some access, 7) by "
            "anyone on site (size: intranet users, 4). Injected commands run as the logged-in user, so "
            "data can be stolen and the system changed (C 7, I 7), and the actions look like the user's (accountability 7).",
        ),
        AttackClass(
            "identity_spoofing",
            "Device identity spoofing / cloning to slip past allowlists",
            ("T1200", "T1036"),
            dict(skill_level=6, motive=9, opportunity=7, size=4, ease_of_discovery=7, ease_of_exploit=5, awareness=6, intrusion_detection=8),
            dict(confidentiality=7, integrity=5, availability=1, accountability=9),
            "Programmable boards let an attacker set any VID/PID/serial (ease of exploit: easy, 5) but it "
            "takes programming skill (6). Allowlists keyed on VID/PID are easy to spot (discovery 7). "
            "A spoofed identity makes the device's actions untraceable to its real owner (accountability: anonymous, 9).",
        ),
        AttackClass(
            "usb_exfiltration",
            "Data exfiltration to removable storage (T1052.001)",
            ("T1052.001",),
            dict(skill_level=1, motive=9, opportunity=7, size=4, ease_of_discovery=7, ease_of_exploit=5, awareness=9, intrusion_detection=8),
            dict(confidentiality=7, integrity=1, availability=1, accountability=7),
            "Copying files needs no technical skill (1) and is common knowledge (9). A large copy is "
            "extensive critical data disclosed (C 7) but changes nothing (I 1, A 1).",
        ),
        AttackClass(
            "removable_media_spread",
            "Malware carried between machines on removable media (T1091)",
            ("T1091",),
            dict(skill_level=3, motive=4, opportunity=7, size=4, ease_of_discovery=7, ease_of_exploit=5, awareness=9, intrusion_detection=8),
            dict(confidentiality=6, integrity=5, availability=5, accountability=7),
            "Removable-media worms need little skill (3) and spread opportunistically (motive: possible "
            "reward, 4). Industrial telemetry (Honeywell GARD 2024) reports about half of USB-borne malware "
            "is designed to spread this way.",
        ),
        AttackClass(
            "evidence_tampering",
            "Tampered agent or forged event times",
            (),  # no clean ATT&CK technique for a forged agent clock
            dict(skill_level=5, motive=4, opportunity=4, size=2, ease_of_discovery=3, ease_of_exploit=3, awareness=4, intrusion_detection=3),
            dict(confidentiality=2, integrity=5, availability=1, accountability=7),
            "Needs administrator access to the agent machine (opportunity: special access, 4; size: system "
            "administrators, 2). It corrupts the investigation timeline (I 5) and hides who did what (accountability 7).",
        ),
    ]
}


@dataclass(frozen=True)
class Indicator:
    attack: str
    confidence: float
    why: str
    standard: str | None = None  # a control or standard the rule implements, beyond ATT&CK
    confidence_variants: tuple[tuple[str, float], ...] = ()  # (detail flag, confidence when it is true)


INDICATORS = {
    "unknown_device": Indicator(
        "keystroke_injection_device", 0.3,
        "Most never-seen devices are new purchases; a rogue device is the minority case.",
        "NIST SP 800-53 MP-7: prohibit portable storage devices with no identifiable owner.",
    ),
    "device_type_mismatch": Indicator(
        "keystroke_injection_device", 0.55,
        "A known identity changing class (storage -> keyboard) is the classic BadUSB firmware trick, "
        "but some composite devices legitimately re-enumerate.",
        "GoodUSB (Tian et al., ACSAC 2015): a device must keep the functionality it claimed.",
    ),
    "descriptor_mismatch": Indicator(
        "keystroke_injection_device", 0.45,
        "The descriptor tree of a known device changed; firmware updates can also do this.",
    ),
    "programmable_hid_board": Indicator(
        "keystroke_injection_device", 0.55,
        "VID/PID belongs to a programmable board family used to build injectors; also used by hobbyists.",
    ),
    "keystroke_injection": Indicator(
        "keystroke_injection_device", 0.9,
        "Typing faster and more regularly than a person can is direct evidence of injection; "
        "macro keyboards and barcode scanners are the known false positives.",
    ),
    "blocklisted_device": Indicator(
        "keystroke_injection_device", 0.8,
        "An investigator already judged this device malicious; the judgement can be wrong or stale.",
    ),
    "serial_reuse_across_models": Indicator(
        "identity_spoofing", 0.8,
        "One serial claimed by two different models almost never happens with genuine hardware.",
    ),
    "serial_format_mismatch": Indicator(
        "identity_spoofing", 0.6,
        "Same model, structurally different serial: typical of a hand-programmed clone.",
    ),
    "missing_serial": Indicator(
        "identity_spoofing", 0.6,
        "Other units of this model report a serial and this one does not.",
    ),
    "descriptor_model_mismatch": Indicator(
        "identity_spoofing", 0.7,
        "The descriptor does not match what this VID/PID is known to look like.",
    ),
    "same_model_new_serial": Indicator(
        "identity_spoofing", 0.2,
        "A second unit of a model already in use is usually a colleague's identical stick.",
    ),
    "large_transfer": Indicator(
        "usb_exfiltration", 0.7,
        "Big copies are often backups; outside working hours the benign explanations thin out.",
        "NIST SP 800-53 MP-7 (restrict media use); MITRE ATT&CK T1052.001.",
        confidence_variants=(("night", 1.0),),
    ),
    "new_source_machine": Indicator(
        "removable_media_spread", 0.6,
        "A stick moving to a machine it has never used is how removable-media malware travels; "
        "people also just change desks.",
    ),
    "future_timestamp": Indicator(
        "evidence_tampering", 0.6,
        "An event dated in the future comes from a wrong agent clock or a forged report.",
    ),
}


def _validate() -> None:
    for a in ATTACKS.values():
        for group, names in ((a.likelihood, LIKELIHOOD_FACTORS), (a.impact, IMPACT_FACTORS)):
            assert set(group) == set(names), f"{a.key}: factors must be exactly {names}"
            for f, v in group.items():
                assert v in ALLOWED[f], f"{a.key}.{f}={v} is not an OWASP option ({sorted(ALLOWED[f])})"
    for name, ind in INDICATORS.items():
        assert ind.attack in ATTACKS, f"{name}: unknown attack class {ind.attack}"
        for _, c in ((None, ind.confidence), *ind.confidence_variants):
            assert 0 <= c <= 1, f"{name}: confidence must be in [0, 1]"


_validate()


def confidence(name: str, detail: dict | None = None) -> float:
    ind = INDICATORS[name]
    for flag, c in ind.confidence_variants:
        if (detail or {}).get(flag):
            return c
    return ind.confidence


def weight(name: str, detail: dict | None = None) -> float:
    """The rule weight for a finding: evidence confidence x points for its attack's OWASP severity."""
    ind = INDICATORS[name]
    return round(confidence(name, detail) * SEVERITY_POINTS[ATTACKS[ind.attack].severity], 1)


def assessment(name: str, detail: dict | None = None) -> dict | None:
    """How a finding's weight was derived, for the risk explanation. None for unrated findings (ML)."""
    ind = INDICATORS.get(name)
    if ind is None:
        return None
    a = ATTACKS[ind.attack]
    return {
        "method": "OWASP Risk Rating x evidence confidence",
        "attack": a.title,
        "likelihood": a.likelihood_score,
        "likelihood_level": band(a.likelihood_score),
        "impact": a.impact_score,
        "impact_level": band(a.impact_score),
        "severity": a.severity,
        "severity_points": SEVERITY_POINTS[a.severity],
        "confidence": confidence(name, detail),
        "standard": ind.standard,
    }


def table() -> list[dict]:
    """Every rated finding, for the docs and the /standards endpoint."""
    return [{"finding": n, "weight": weight(n), **assessment(n), "confidence_reason": i.why} for n, i in INDICATORS.items()]
