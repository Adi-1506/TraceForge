# How TraceForge scores risk, and which standards it rests on

There is no published standard that scores the risk of an individual USB device. TraceForge
therefore builds its score out of standards and literature that each cover one part of the
problem, so that no number in it is unexplained:

| Question | Answered by |
| --- | --- |
| How do we combine likelihood and impact into a severity? | OWASP Risk Rating Methodology, the factor-based instance of the likelihood x impact model in NIST SP 800-30 Rev. 1 |
| Why does a rule exist at all? | NIST SP 800-53 Rev. 5 MP-7 (Media Use), GoodUSB, the USB attack taxonomies |
| Which attack does a finding point to? | MITRE ATT&CK techniques T1200, T1036, T1059, T1091, T1052.001 |
| How sure are we that a finding means that attack? | An analyst prior per rule, checked against labelled scenarios (`server/scoring/calibrate.py`) |
| How good is the detector? | `server/evaluate.py`, compared with published detectors (USBeSafe) |

The code is `server/scoring/standards.py`; `GET /standards` returns the same tables, and every
risk explanation in the dashboard shows the OWASP rating behind each weight.

## The formula

```
weight(finding) = confidence(finding) x SEVERITY_POINTS[ OWASP severity of the attack it indicates ]
score(event)    = 5 baseline + sum of weights, capped at 100
level           = low < 25 <= medium < 50 <= high < 75 <= critical
```

`SEVERITY_POINTS` are `Note 0, Low 10, Medium 25, High 50, Critical 75`: the same numbers as the
level bands. So one fully confident finding of OWASP severity S places a connection in level S
on its own, weaker evidence is discounted by its confidence, and independent findings add up
(corroboration).

Two questions are kept apart on purpose. OWASP rates **how bad an attack is** (likelihood x impact).
It says nothing about **how strongly one observation indicates that attack**: most never-seen
devices are new purchases, not rogue hardware. That second question is the confidence `c`.

## Step 1: OWASP rating of each attack class

Each factor uses only the option values OWASP defines (`server/scoring/standards.py` rejects any
other value at import). Likelihood = mean of the 8 likelihood factors, impact = mean of the 4
technical-impact factors; each is LOW below 3, MEDIUM below 6, HIGH otherwise, and the OWASP matrix
gives the severity.

| Attack class | skill | motive | opportunity | size | discovery | exploit | awareness | intrusion detection | **L** | conf. | integ. | avail. | account. | **I** | **Severity** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Rogue HID / keystroke injection (T1200, T1059) | 5 | 9 | 7 | 4 | 7 | 9 | 9 | 8 | 7.25 HIGH | 7 | 7 | 5 | 7 | 6.5 HIGH | **Critical** |
| Identity spoofing / cloning (T1200, T1036) | 6 | 9 | 7 | 4 | 7 | 5 | 6 | 8 | 6.5 HIGH | 7 | 5 | 1 | 9 | 5.5 MEDIUM | **High** |
| Exfiltration to USB storage (T1052.001) | 1 | 9 | 7 | 4 | 7 | 5 | 9 | 8 | 6.25 HIGH | 7 | 1 | 1 | 7 | 4.0 MEDIUM | **High** |
| Malware spread on removable media (T1091) | 3 | 4 | 7 | 4 | 7 | 5 | 9 | 8 | 5.88 MEDIUM | 6 | 5 | 5 | 7 | 5.75 MEDIUM | **Medium** |
| Tampered agent / forged event time | 5 | 4 | 4 | 2 | 3 | 3 | 4 | 3 | 3.5 MEDIUM | 2 | 5 | 1 | 7 | 3.75 MEDIUM | **Medium** |

Rating conventions:
- **Intrusion detection** is rated for the machine as it would be *without* TraceForge: Windows and
  Linux record the device in their PnP logs, but nobody reviews them ("logged without review", 8).
  The rating describes the exposure TraceForge exists to reduce.
- **Opportunity** for every USB attack is "some access required" (7): it needs a moment of physical
  access, nothing more.
- The written reason for every rating is in `ATTACKS[...].why` in the code and in `GET /standards`.

## Step 2: evidence confidence per finding

| Finding | Indicates | OWASP severity | Confidence c | Weight | ATT&CK | Standard it implements |
| --- | --- | --- | --- | --- | --- | --- |
| `unknown_device` | keystroke injection device | Critical | 0.30 | 22.5 | T1200 | NIST SP 800-53 MP-7: no portable storage without an identifiable owner |
| `device_type_mismatch` | keystroke injection device | Critical | 0.55 | 41.2 | T1200, T1036, T1059 | GoodUSB: a device keeps the functionality it claimed |
| `descriptor_mismatch` | keystroke injection device | Critical | 0.45 | 33.8 | T1200, T1036 | |
| `programmable_hid_board` | keystroke injection device | Critical | 0.55 | 41.2 | T1200, T1059 | |
| `keystroke_injection` | keystroke injection device | Critical | 0.90 | 67.5 | T1200, T1059 | |
| `blocklisted_device` | keystroke injection device | Critical | 0.80 | 60.0 | T1200 | |
| `serial_reuse_across_models` | identity spoofing | High | 0.80 | 40.0 | T1200, T1036 | |
| `serial_format_mismatch` | identity spoofing | High | 0.60 | 30.0 | T1200, T1036 | |
| `missing_serial` | identity spoofing | High | 0.60 | 30.0 | T1200 | |
| `descriptor_model_mismatch` | identity spoofing | High | 0.70 | 35.0 | T1200, T1036 | |
| `same_model_new_serial` | identity spoofing | High | 0.20 | 10.0 | T1200, T1036 | |
| `large_transfer` | USB exfiltration | High | 0.70 (night 1.0) | 35.0 (night 50.0) | T1052.001 | NIST SP 800-53 MP-7 |
| `new_source_machine` | removable-media spread | Medium | 0.60 | 15.0 | T1091 | |
| `future_timestamp` | evidence tampering | Medium | 0.60 | 15.0 | | |

The ML findings (`behavioural_outlier`, `unseen_behaviour`) are not OWASP-rated: an unusual
pattern alone does not name an attack, so their weight is the model's scaled anomaly score, the
same reason they carry no ATT&CK technique.

A useful sanity check: before this rating existed, the rules had hand-picked weights
(25, 40, 40, 35, 35, 30, 10, 40, 60, 60, 35/50, 15). The derived weights land within a few points
of every one of them, so the original intuitions and the standard agree.

## Step 3: checking the confidences against data

```bash
python -m server.scoring.calibrate --seeds 1 2 3
```

This replays the labelled scenarios of `server/evaluate.py` and reports each finding's empirical
precision, P(attack | finding fired), with a Laplace estimate, next to the prior, plus the log-odds
from an L2 logistic regression over all findings. Result:

| Finding | Fired | Measured precision | Prior c |
| --- | --- | --- | --- |
| `unknown_device` | 65 | 0.63 | 0.30 |
| `device_type_mismatch` | 24 | 0.96 | 0.55 |
| `descriptor_mismatch` | 48 | 0.98 | 0.45 |
| `keystroke_injection` | 48 | 0.98 | 0.90 |
| `serial_reuse_across_models` | 118 | 0.99 | 0.80 |
| `missing_serial` | 17 | 0.95 | 0.60 |
| `large_transfer` | 24 | 0.96 | 0.70 |
| `new_source_machine` | 14 | 0.88 | 0.60 |

Every measured precision is *above* its prior. That is expected, and it is why the priors were not
raised to match: the synthetic data has only three kinds of benign look-alike (a new keyboard, a
person typing, a daytime copy), while a real organisation has many more (firmware updates, docking
stations, macro keyboards, backup jobs). Synthetic precision is an upper bound; the priors stay
deliberately conservative. The ordering agrees: `keystroke_injection` and `serial_reuse_across_models`
are the most diagnostic in both, `unknown_device` the least.

## References

- OWASP Foundation, *OWASP Risk Rating Methodology*. https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
- NIST SP 800-30 Rev. 1, *Guide for Conducting Risk Assessments* (2012).
- NIST SP 800-53 Rev. 5, control MP-7 *Media Use*. https://csf.tools/reference/nist-sp-800-53/r5/mp/mp-7/
- MITRE ATT&CK: T1200 Hardware Additions, T1036 Masquerading, T1059 Command and Scripting Interpreter,
  T1091 Replication Through Removable Media, T1052.001 Exfiltration over USB. https://attack.mitre.org
- D. J. Tian, N. Scaife, D. Kumar, M. Bailey, A. Bates, K. R. B. Butler, *SoK: "Plug & Pray" Today -
  Understanding USB Insecurity in Versions 1 through C*, IEEE S&P 2018. Finds that USB attacks exploit
  trust-by-default and that multi-layer defences work best, which is TraceForge's rules + ML + trust design.
- N. Nissim, R. Yahalom, Y. Elovici, *USB-based attacks*, Computers & Security 70 (2017) 675-688.
  Taxonomy of 29 USB attacks in four categories.
- D. J. Tian, A. Bates, K. R. B. Butler, *Defending Against Malicious USB Firmware with GoodUSB*, ACSAC 2015.
  Basis for `device_type_mismatch` and `programmable_hid_board`.
- A. Kharraz, B. L. Daley, G. Z. Baker, W. Robertson, E. Kirda, *USBESAFE: An End-Point Solution to
  Protect Against USB-Based Attacks*, RAID 2019. Reports 95.7% detection at 0.21% false positives;
  the benchmark TraceForge's evaluation is compared with.
- K. Denney, E. Erdin, L. Babun, M. Vai, S. Uluagac, *USB-Watch: A Dynamic Hardware-Assisted USB Threat
  Detection Framework*, SecureComm 2019.
- S. Neuner et al., *USBlock: Blocking USB-Based Keypress Injection Attacks*, IFIP (Springer LNCS), 2018.
- G. Karantzas, *Forensic Log Based Detection For Keystroke Injection "BadUSB" Attacks*, arXiv:2302.04541 (2023).
  Detects injection by comparing keystroke bursts with human typing by inspection; TraceForge makes the
  thresholds explicit (rate, regularity, burst fraction).
- Honeywell GARD, *USB Threat Report 2024*. USB-borne malware rose from 9% (2019) to 51% of detections.
- Population Stability Index bands (0.10 / 0.25) used by `/ml/drift` are an industry convention from
  credit-risk model monitoring, not a formal standard.
