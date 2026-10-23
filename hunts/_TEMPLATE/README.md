# H-00X · <short title>

| | |
| --- | --- |
| **ATT&CK** | [T____ Name](https://attack.mitre.org/techniques/T____/) |
| **Tactic** | |
| **Dataset** | OTRF APT29 Evals, day 1 (`otrf-apt29-day1`) |
| **Data source** | Event IDs used |
| **Verdict** | True positive / benign true positive / not present (scoped negative) / not visible |
| **Validated by** | [`hunt.yml`](hunt.yml); evidence in `results/H-00X.json` |

## Hypothesis

One or two sentences: if an attacker did X, we would see Y in data source Z.

**Scope:** hosts, time window, data source.

**Prerequisite:** what logging must be on for this hunt to mean anything.

## Terms

Define anything a reader might not know.

## Method and results

| Step | Query | Hits | What it showed |
| --- | --- | --- | --- |
| 1 · Scope | `q1-...` | | The population, then stack it |
| 2 · Signal | `q2-...` | | |
| 3 · Tuned | `q3-...` | | |
| 4 · Pivot | `q4-...` | | |

Paste the stack table for step 1 here, from `results/H-00X.json`.

## False positives and tuning

What matched that wasn't malicious, why, and how you removed it without opening a blind spot.

## Detection proposal

Link a Sigma rule (`detection.yml`) or explain why this stays a hunt and not an alert.

## Response notes

What a responder does first if this fires for real.

<!--
A scoped negative is a real result. Write it like this:
"<Technique> not present across <hosts>, <window>, checked via <data sources>.
Not visible on <uncovered assets>."
-->
