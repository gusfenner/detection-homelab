# Detection Rules Reference

Custom Wazuh rules for this lab are in `ansible/roles/wazuh_server/files/local_rules.xml`.
Rule IDs 100001–100099 are reserved for lab-specific detection logic.

---

## Rule Design Principles

1. **Use `<if_group>sysmon`** — all rules match only on Sysmon-decoded events, reducing false positives from other log sources
2. **MITRE `<id>` tags** — every rule includes ATT&CK technique IDs so alerts appear in the Wazuh MITRE view
3. **Severity ladder** — level 10 = suspicious, level 12 = malicious, level 15 = critical (response triggered)
4. **Regex on decoded fields** — match against `data.sysmon.*` fields produced by `local_decoders.xml`

---

## Rule 100001 — T1053.003: Crontab Invoked

```xml
<rule id="100001" level="10">
  <if_group>sysmon</if_group>
  <field name="data.sysmon.eventid">^1$</field>
  <field name="data.sysmon.image">crontab</field>
  <description>ATT&amp;CK T1053.003 - Crontab invoked</description>
  <mitre><id>T1053.003</id></mitre>
</rule>
```

**Why it fires:** Any `ProcessCreate` (EventID 1) where the image path contains `crontab`.  
**False positive rate:** Low. Legitimate crontab invocations by admins are infrequent and auditable.  
**Tuning:** Add `<field name="data.sysmon.user">!root</field>` to escalate when non-root runs crontab.

---

## Rule 100002 — T1053.003: File Written to Cron Directory

```xml
<rule id="100002" level="12">
  <if_group>sysmon</if_group>
  <field name="data.sysmon.eventid">^11$</field>
  <field name="data.sysmon.targetfilename">/etc/cron\.|/var/spool/cron/</field>
  <description>ATT&amp;CK T1053.003 - File written to cron directory</description>
  <mitre><id>T1053.003</id></mitre>
</rule>
```

**Why it fires:** `FileCreate` (EventID 11) targeting cron directories.  
**Ideal response:** Alert + FIM diff to identify exact content added.

---

## Rule 100010 — T1059.004: Reverse Shell Pattern

```xml
<rule id="100010" level="15">
  <if_group>sysmon</if_group>
  <field name="data.sysmon.eventid">^1$</field>
  <field name="data.sysmon.commandline">/dev/tcp/|/dev/udp/|mkfifo|nc -e|ncat -e|bash -i</field>
  <description>ATT&amp;CK T1059.004 - Reverse shell pattern detected</description>
  <mitre><id>T1059.004</id></mitre>
</rule>
```

**Why level 15:** Reverse shell syntax has virtually no legitimate use on a server. Immediate response warranted.  
**Ideal Active Response:** Block outbound TCP on the destination port via `iptables` + isolate agent.

---

## Rule 100020 — T1055: CreateRemoteThread

```xml
<rule id="100020" level="15">
  <if_group>sysmon</if_group>
  <field name="data.sysmon.eventid">^8$</field>
  <description>ATT&amp;CK T1055 - CreateRemoteThread detected</description>
  <mitre><id>T1055</id></mitre>
</rule>
```

**Why it fires:** Any `CreateRemoteThread` event (EventID 8) is inherently suspicious on Linux.  
**Note:** On Linux, CreateRemoteThread maps to `clone()` or `pthread_create()` targeting a foreign process.

---

## Rule 100030 + 100031 — T1136.001: Account Creation + Privilege Escalation

```xml
<rule id="100030" level="10">  <!-- useradd detected -->
<rule id="100031" level="15">  <!-- usermod → sudo group -->
```

**Correlation opportunity:** If both 100030 and 100031 fire within 60 seconds from the same agent,
a Level 15 composite alert can be triggered using `<frequency>` and `<timeframe>` in a correlation rule:

```xml
<rule id="100032" level="15" frequency="2" timeframe="60">
  <if_matched_sid>100030</if_matched_sid>
  <if_matched_sid>100031</if_matched_sid>
  <description>ATT&amp;CK T1136.001 - Account created AND added to sudo within 60s</description>
  <mitre><id>T1136.001</id><id>T1548.003</id></mitre>
</rule>
```

---

## Rule 100040 + 100041 — T1070.003: Indicator Removal

```xml
<rule id="100040" level="12">  <!-- history -c or HISTFILE -->
<rule id="100041" level="12">  <!-- truncate /var/log/* -->
```

**Why this matters:** Log clearing is often the *last* action before an attacker exits.
Detecting it in near-real-time via Sysmon (before the logs are gone) is the key advantage of EDR-level telemetry.

**Detection gap:** If the attacker clears logs before the Wazuh agent forwards them, L0 is lost.
L1/L2 events may still be present if the agent already forwarded partial logs.

---

## Wazuh Active Response Configuration

Add to `/var/ossec/etc/ossec.conf` on the manager to trigger automatic IP blocking on Level 15 alerts:

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <level>15</level>
  <timeout>600</timeout>
</active-response>
```

---

## Detection Summary Table

| Rule ID | Level | Technique | EventID | Action |
|---|---|---|---|---|
| 100001 | 10 | T1053.003 | 1 | Alert: Crontab invoked |
| 100002 | 12 | T1053.003 | 11 | Alert: File in cron dir |
| 100010 | 15 | T1059.004 | 1 | Alert + Response: Reverse shell |
| 100011 | 10 | T1059.004 | 1 | Alert: Base64 obfuscation |
| 100020 | 15 | T1055 | 8 | Alert + Response: Remote thread |
| 100021 | 12 | T1055 | 10 | Alert: ptrace / /proc/mem |
| 100030 | 10 | T1136.001 | 1 | Alert: Account creation |
| 100031 | 15 | T1136.001 | 1 | Alert + Response: Sudo escalation |
| 100040 | 12 | T1070.003 | 1 | Alert: History cleared |
| 100041 | 12 | T1070.003 | 1 | Alert: Log file truncated |
