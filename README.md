# Threat Hunt Library

![Validate hunts](https://github.com/cooke-labs/threat-hunt-library/actions/workflows/validate-hunts.yml/badge.svg)

Hypothesis-driven threat hunts against public adversary-emulation data, mapped to
MITRE ATT&CK. Every hunt ships as two files:

- **`README.md`**: the write-up. Hypothesis, scope, each query and what it returned,
  false positives, tuning, and a detection proposal.
- **`hunt.yml`**: the same queries in machine-readable form, each with the hit count the
  write-up claims.

[`scripts/run_hunts.py`](scripts/run_hunts.py) runs every query exactly as written and
records the results in [`results/`](results/). The [CI workflow](.github/workflows/validate-hunts.yml)
loads the dataset into a fresh Elasticsearch on every push and fails if any count
changes. The badge above is green only if every hunt still finds what it says it finds.

## Hunts

| ID | Technique | Hunt | Verdict |
| --- | --- | --- | --- |
| [H-001](hunts/H-001-lsass-access/) | T1003.001 | LSASS memory access from unbacked code | True positive, 2 hosts |
| H-002 | T1036.002 | Right-to-left override in filenames | Planned |
| H-003 | T1548.002 | UAC bypass through auto-elevating binaries | Planned |
| H-004 | T1059.001 | Hidden, policy-bypassing PowerShell (script block logging, 4104) | Planned |
| H-005 | T1027.003 | Payloads reconstructed from image files | Planned |
| H-006 | T1021.006 | Lateral movement over WinRM | Planned |
| H-007 | T1547.001 / T1543.003 | Persistence through Run keys and new services | Planned |
| H-008 | T1071 | Command-and-control beaconing in Sysmon 3 and Zeek | Planned |

## Data

[OTRF Security-Datasets: APT29 Evals](https://github.com/OTRF/Security-Datasets/tree/master/datasets/compound/apt29),
day 1. 196,081 Windows events (Sysmon, Security, PowerShell) from 4 hosts, recorded
during the MITRE ATT&CK Evaluations emulation of APT29.

## Run it yourself

Requires Python 3.9+ and Elasticsearch 8.x.

```bash
pip install pyyaml
curl -fsSLO https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip

export ES_URL=https://localhost:9200 ES_USER=elastic ES_PASS='<password>' ES_CA_CERT=<path to http_ca.crt>
python3 scripts/load_otrf.py apt29_evals_day1_manual.zip --index otrf-apt29-day1 --recreate
python3 scripts/run_hunts.py
```

## Method

1. **Scope before querying:** technique, host set, time window, data source. A clean
   result is only meaningful against a stated scope.
2. **Stack first:** count the population by field and look at the rare rows. With no
   baseline, the fleet is the baseline.
3. **Ask what would have to be true for it to be malicious,** and check the cheapest
   condition first.
4. **Pivot on every hit:** parent, children, network, identity. Real intrusions have
   neighbors.
5. **Write up negatives:** "not present in scope" and "not visible" are findings.
