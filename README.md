
# 🕵️ Internal Reconnaissance via PowerShell-Based Port Scanning

## 📘 Scenario Overview

During routine performance monitoring, the server team observed significant network performance degradation across older devices within the `10.0.0.0/16` internal network. External threats such as DDoS attacks were ruled out early in the investigation. The Security Operations team was then tasked with exploring the possibility of internal reconnaissance or misuse of network resources.

## 🧠 Hypothesis

In the current network setup:
- All traffic originating from the internal network is implicitly trusted.
- There is no application control or PowerShell restriction in place.

It is possible that:
- A compromised internal host or malicious insider is performing unauthorized reconnaissance.
- Port scanning activity or unauthorized large file transfers may be degrading the network.

## 🔍 Investigation Steps

### Step 1: Identify Hosts with Unusual Connection Failures

We started by querying all devices reporting a high volume of failed connection attempts — a potential sign of scanning behavior.

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize FailedConnectionsAttempts = count() by DeviceName, ActionType, LocalIP
| order by FailedConnectionsAttempts desc
```
![query1_focus_on_windows_target](https://github.com/user-attachments/assets/c97790d9-f870-44c7-b8d2-302675eb27ec)


The device **`windows-target-1`** surfaced at the top with a significantly high number of failed connections.

---

### Step 2: Filter for Target Device IP

```kql
let IPInQuestion = "10.0.0.5";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| summarize FailedConnectionsAttempts = count() by DeviceName, ActionType, LocalIP
| order by FailedConnectionsAttempts desc
```

![query1_windows_target_1](https://github.com/user-attachments/assets/4b764720-7f11-4b9c-be40-f54d522c6b22)


---

### Step 3: Analyze Failed Connections by Port

Analyzing the failed outbound connections revealed attempts on a wide range of well-known ports, consistent with common port scanning behavior.

```kql
let IPInQuestion = "10.0.0.5";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort
```

![query2_well_known_ports](https://github.com/user-attachments/assets/c91127e6-970b-4610-9c97-2fefc4c6bb6e)


---

### Step 4: Pivot to Process Activity for Attribution

We correlated the timestamp of the connection failures with running processes to trace the source.

```kql
let VMName = "windows-target-1";
let specificTime = datetime(2025-04-12T16:18:37.5180794Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 20m) .. (specificTime + 20m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```

![query3_final](https://github.com/user-attachments/assets/a4d1dd0c-fd3d-4534-833e-4e929d4d31e1)


A PowerShell script named **`portscan.ps1`** was executed during this timeframe, strongly indicating intentional scanning activity from this host.

---

## ⚔️ MITRE ATT&CK Mapping

| Tactic              | Technique                              | ID             | Description                                                |
|---------------------|----------------------------------------|----------------|------------------------------------------------------------|
| Discovery           | Network Service Scanning               | T1046          | Scanning internal network to identify active services.     |
| Execution           | PowerShell                             | T1059.001      | Execution of a PowerShell script (portscan.ps1).           |

---

## 🛡️ Mitigation Strategies

- **Limit PowerShell Usage**  
  Use AppLocker or WDAC policies to restrict unauthorized PowerShell scripts.

- **Enable Network Firewall Rules**  
  Restrict lateral traffic by default and allow only necessary internal services.

- **Network Segmentation**  
  Isolate critical infrastructure from general user segments to limit movement.

- **Implement Application Control**  
  Block unauthorized scripts or executables from being executed on endpoints.

- **Monitor and Alert on PowerShell Execution**  
  Leverage Defender for Endpoint or other EDR tools to alert on suspicious scripting activity.

---

## 🧯 Remediation Recommendations

- **Immediate Containment**  
  Isolate `windows-target-1` from the network to prevent further scanning or lateral movement.

- **Forensic Analysis**  
  Retrieve and analyze `portscan.ps1` for intent and potential data exfiltration behavior.

- **Credential Audit**  
  Check if the user who ran the script has elevated privileges or reused credentials.

- **Review Group Policy / Device Compliance**  
  Harden GPOs to restrict unrestricted PowerShell access on endpoints.

- **User Awareness Training**  
  Educate employees on acceptable use policies and report suspicious activity.

---

📁 _This investigation demonstrates proactive internal threat hunting, leveraging Microsoft Defender XDR telemetry to uncover lateral reconnaissance using native tools. The detection and containment of such behaviors are critical in preventing larger scale intrusions and data exfiltration._
