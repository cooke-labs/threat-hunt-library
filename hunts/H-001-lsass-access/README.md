# H-001 · LSASS memory access from unbacked code

| | |
| --- | --- |
| **ATT&CK** | [T1003.001 OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) |
| **Tactic** | Credential Access |
| **Dataset** | OTRF APT29 Evals, day 1 (`otrf-apt29-day1`, 196,081 events, 4 hosts) |
| **Data source** | Sysmon Event ID 10 (ProcessAccess), Sysmon Event ID 1 (ProcessCreate) |
| **Verdict** | **True positive.** Credential dumping on SCRANTON and NASHUA by user `DMEVALS\pbeesly` |
| **Validated by** | [`hunt.yml`](hunt.yml), run by [`scripts/run_hunts.py`](../../scripts/run_hunts.py); evidence in [`results/H-001.json`](../../results/H-001.json) |

## Hypothesis

If an attacker has code running on a host with admin rights, they will try to read
credentials out of LSASS, the Windows process that holds logon secrets in memory.
In-memory tools leave two traces when they do it: they ask for a handle with rights
that allow reading memory, and the request comes from code that isn't backed by a
file on disk.

**Scope:** all 4 hosts, the full day-1 window (2020-05-02 02:55–03:28 UTC), Sysmon 10
events whose target is `lsass.exe`.

**Prerequisite:** the Sysmon config must log ProcessAccess for `lsass.exe`. Many
configs don't, because LSASS access is noisy. If your environment has no Sysmon 10
events for LSASS, the negative result means "not visible," not "not present."

## Terms

- **Handle / access mask (`GrantedAccess`):** when one process opens another, it asks
  for specific rights, encoded as a hex bitmask. `0x1000` only queries basic info.
  `0x0010` (`PROCESS_VM_READ`) reads memory, which is what credential theft needs.
  `0x1fffff` is every right.
- **Call trace (`CallTrace`):** the chain of code that made the request. Each entry is
  normally a DLL on disk. `UNKNOWN(<address>)` means the code lives in memory with no
  file behind it: reflectively loaded tools, shellcode, or just-in-time-compiled code.
- **Stacking:** counting events by a field to find what's rare. With no baseline, the
  fleet is the baseline.

## Method and results

| Step | Query | Hits | What it showed |
| --- | --- | --- | --- |
| 1 · Scope | `q1-scope` | 326 | 15 distinct source-process/mask pairs. 286 are `svchost.exe` at `0x1000` |
| 2 · Signal A | `q2-unbacked-calltrace` | 9 | Catches the attack, plus 4 false positives from Azure agents (.NET code compiled at runtime) |
| 3 · Signal B | `q3-high-access-mask` | 5 | Catches the attack, plus 2 false positives: `wininit.exe` and `csrss.exe`, which legitimately hold full access |
| 4 · Combine | `q4-tuned-detection` | **3** | Both signals together: zero false positives in this dataset |
| 5 · Pivot | `q5-pivot-children` | 4 | The dumping PowerShell process launched `csc.exe` and two more PowerShell processes |
| 6 · Pivot | `q6-pivot-same-chain-low-mask` | 2 | One child also touched LSASS at `0x1000`, which the rule ignores on purpose |

### Step 1 stack: who touches LSASS

| Count | Source process | Mask | Read |
| ---: | --- | --- | --- |
| 286 | `svchost.exe` | 0x1000 | Normal |
| 13 | `AntimalwareConfig.exe` | 0x1400 | Normal (Azure agent) |
| 11 | `WindowsAzureTelemetryService.exe` | 0x1400 | Normal (Azure agent) |
| 1 | `PowerShell.exe` | 0x1f3fff | **Rare: PowerShell with near-full access** |
| 1 | `PowerShell.exe` | 0x1fffff | **Rare: PowerShell with full access** |
| 1 | `wsmprovhost.exe` | 0x1f3fff | **Rare: remote PowerShell host with near-full access** |
| 1 | `wininit.exe`, `csrss.exe` | 0x1fffff | Normal (system processes that start LSASS) |

The rare rows are three processes no baseline would expect to need full access to LSASS.

Note: keyword stacking is case-sensitive. `powershell.exe` and `PowerShell.exe` land in
separate buckets. Normalize case at ingest, or the rarest-looking row can be a casing
artifact.

### The three hits

| Time (UTC) | Host | Process | Mask |
| --- | --- | --- | --- |
| 03:05:16.623 | SCRANTON | `PowerShell.exe` (PID 2976) | 0x1f3fff |
| 03:05:16.654 | SCRANTON | `PowerShell.exe` (PID 2976) | 0x1fffff |
| 03:09:29.430 | NASHUA | `wsmprovhost.exe` (PID 7720) | 0x1f3fff |

### Pivot: where did PID 2976 come from?

Walking the parent chain with Sysmon 1:

```
02:55:56  cod.3aka3.scr /S        C:\ProgramData\victim\   (filename uses a right-to-left override character)
02:57:12   └ cmd.exe
02:58:43     └ sdclt.exe          (known UAC bypass)
02:58:43       └ control.exe /name Microsoft.BackupAndRestoreCenter
02:58:44         └ PowerShell.exe -noni -noexit -ep bypass -window hidden
                    (rebuilds a payload from pixels in Downloads\monkey.png)
03:05:16           → opens LSASS with full access, from unbacked memory
```

Every link is a separate lead: masquerading (T1036.002), UAC bypass (T1548.002),
PowerShell (T1059.001), and steganography (T1027.003). Each becomes its own hunt.

On NASHUA, `wsmprovhost.exe` is the process Windows starts to run a **remote**
PowerShell session (WinRM). The same user, `pbeesly`, logged on to NASHUA over the
network seconds before. Credentials taken on SCRANTON were likely used to move laterally
(T1021.006) and dump again. That's hunt H-006.

## False positives and tuning

| Signal | Hits | False positives | Why |
| --- | ---: | ---: | --- |
| Unbacked call trace alone | 9 | 4 | Azure agents run .NET code compiled at runtime, which also shows as `UNKNOWN` |
| High access mask alone | 5 | 2 | `wininit.exe` and `csrss.exe` hold full access by design |
| Both together | 3 | 0 | Neither benign pattern does both |

Tuning choices:

- **Combine signals before excluding anything.** No exclusion list is needed in this
  dataset, so nothing can hide behind one.
- **If an exclusion is ever needed,** scope it to full path plus signer plus mask, never
  a process name alone. An attacker can name their tool `AntimalwareConfig.exe`.
- **Known gap:** the rule misses the child PowerShell that touched LSASS at `0x1000`
  (`q6`). Low masks are too common to alert on. The pivot caught it, which is why every
  alert from this rule should start with an ancestry and child-process pivot.
- **Known gap:** tools that open LSASS through a duplicated handle, or that dump through
  a signed binary such as `comsvcs.dll` with `rundll32`, can avoid one or both signals.
  Pair this rule with a process-creation rule for dump command lines.

## Detection proposal

Sigma rule: [`detection.yml`](detection.yml). Severity high; expected volume is near zero
in a normal fleet.

## Response notes

If this fires for real: isolate the host, capture memory before reboot, and treat every
credential cached on that host as compromised. Reset those accounts and check where they
logged on since the alert time, starting with network logons (type 3) from the source host.
