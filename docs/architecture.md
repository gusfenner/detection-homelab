# Detection Home Lab — Architecture

## System Architecture

```mermaid
graph TB
    subgraph HOST["🖥️ Windows Host (VirtualBox + Vagrant)"]
        subgraph PRIV["Private Network — 192.168.56.0/24"]

            subgraph WS["wazuh-server (192.168.56.10)"]
                WM["Wazuh Manager\n(ossec)"]
                WI["Wazuh Indexer\n(OpenSearch)"]
                WD["Wazuh Dashboard\n(port 443)"]
                WM --> WI
                WI --> WD
            end

            subgraph AN["agent-node (192.168.56.20)"]
                SYS["Sysmon4Linux\n(EventID 1,3,8,10,11)"]
                RSL["rsyslog\n(UDP 514 forward)"]
                WA["Wazuh Agent\n(TCP 1514)"]
                SYS --> RSL
                SYS --> WA
            end

            subgraph ATK["attacker (192.168.56.30)"]
                SIM["simulate_attack.sh\nT1053 T1059 T1055\nT1136 T1070"]
            end

        end
    end

    RSL -->|"UDP :514 syslog"| WM
    WA  -->|"TCP :1514 agent"| WM
    SIM -->|"SSH attack\nor local exec"| AN

    style HOST fill:#1a1a2e,stroke:#16213e,color:#eee
    style WS   fill:#0f3460,stroke:#533483,color:#eee
    style AN   fill:#533483,stroke:#e94560,color:#eee
    style ATK  fill:#e94560,stroke:#e94560,color:#fff
```

## Component Details

| Component | VM | IP | Role |
|---|---|---|---|
| Wazuh Manager | wazuh-server | 192.168.56.10 | SIEM core — receives, parses, and correlates events |
| Wazuh Indexer | wazuh-server | 192.168.56.10 | OpenSearch-based event storage and search |
| Wazuh Dashboard | wazuh-server | 192.168.56.10 | Kibana-like UI for alert visualization |
| Sysmon4Linux | agent-node | 192.168.56.20 | Kernel-level event capture (processes, network, files) |
| Wazuh Agent | agent-node | 192.168.56.20 | Forwards Sysmon + system logs to Manager |
| Attack Simulator | attacker | 192.168.56.30 | Executes MITRE ATT&CK technique simulations |

## Data Flow

```
Attack Script → Linux Kernel Syscall
                     ↓
               Sysmon4Linux (EventID capture)
                     ↓
               /var/log/syslog (JSON/XML event)
                     ↓
         ┌──────────────────────┐
         │   rsyslog (UDP 514)  │  ← EventID 3, 8, 10 (network-based)
         └──────────┬───────────┘
                    ↓
         ┌──────────────────────┐
         │    Wazuh Agent       │  ← All other events via localfile
         └──────────┬───────────┘
                    ↓
         ┌──────────────────────┐
         │   Wazuh Manager      │
         │  (Decoder → Rules)   │
         └──────────┬───────────┘
                    ↓
         ┌──────────────────────┐
         │   Wazuh Indexer      │
         │  (OpenSearch store)  │
         └──────────┬───────────┘
                    ↓
         ┌──────────────────────┐
         │  Wazuh Dashboard     │
         │  (Alert + MITRE tag) │
         └──────────────────────┘
```

## Networking

| Network | CIDR | Purpose |
|---|---|---|
| NAT (eth0) | 10.0.2.0/24 | Vagrant default — internet access for provisioning |
| Host-Only (eth1) | 192.168.56.0/24 | Lab internal — VM-to-VM + host-to-VM communication |
