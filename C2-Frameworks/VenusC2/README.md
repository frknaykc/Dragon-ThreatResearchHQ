# Venus C2 Dashboard

## Overview

**Type:** Command & Control Framework  
**Framework:** Venus C2  
**Version:** 0.5.1  
**IP Address:** 45.8.157.134  
**Risk Level:** 🔴 HIGH  
**Category:** Red Team / Adversary C2  
**Status:** ✅ Active (Version 0.5.1 indicates ongoing development)  

---

## Visual Indicators

### Dashboard Layout
- Dark blue/navy themed dashboard
- "Venus C2" title with version number display
- Modular panel layout with distinct sections
- Multi-colored progress bars (purple, blue, cyan, orange, yellow)
- Clean, professional interface

### Dashboard Modules
1. **Online Agents** - Real-time agent counter
2. **Data Exfiltration** - Exfiltration statistics
3. **Native Modules (Payloads)** - Color-coded payload bars
4. **Agents** - Table view with agent details
5. **Command History** - Executed command log
6. **Control Panel** - Operator interface
7. **Exfiltrated Files** - Stolen data repository
8. **System Reports** - System analytics

---

## Detection Fingerprints

### Text Patterns
```
- "Venus C2 Dashboard"
- "Venus C2 (semver 0.5.1)"
- "Online Agents"
- "Data Exfiltration"
- "Native Modules (Payloads)"
- "Command History"
- "Exfiltrated Files"
- "System Reports"
- "Control Panel"
```

### Network Indicators
- Web-based C2 interface (likely HTTP/HTTPS)
- Agent check-in endpoint
- Command queue system
- File exfiltration capability
- Real-time agent status monitoring
- WebSocket connections (for live updates)

---

## Shodan/Censys Queries

```bash
# Shodan
http.title:"Venus C2"
http.html:"Venus C2 Dashboard"
http.html:"semver 0.5.1"
http.html:"Online Agents" http.html:"Native Modules"
ip:45.8.157.134
http.html:"Venus C2" http.html:"Command History"

# Censys
services.http.response.html_title:"Venus C2"
services.http.response.body:"Venus C2 Dashboard"
services.http.response.body:"semver 0.5.1"
ip:45.8.157.134
services.http.response.body:"Exfiltrated Files" AND services.http.response.body:"Control Panel"
```

---

## Technical Capabilities

### Agent Management
- Real-time agent status monitoring
- Agent registration and deregistration
- Agent metadata collection (OS, IP, hostname)
- Agent grouping and filtering
- Multi-agent orchestration

### Command & Control
- Command execution on remote agents
- Command history tracking
- Command queue management
- Scheduled task execution
- Script execution (PowerShell, Bash, etc.)

### Data Exfiltration
- File upload/download
- Screen capture
- Keylogging
- Clipboard monitoring
- Credential harvesting
- Browser data collection

### Payload Delivery
- Native module deployment
- In-memory execution
- Staged payload delivery
- Custom payload builder
- Multi-platform support

### Operational Security
- HTTPS/TLS encryption
- Session management
- Operator authentication
- Activity logging
- Campaign segregation

---

## Known Infrastructure

### Primary C2 Server
```
IP: 45.8.157.134
Version: 0.5.1
Status: Active (February 2026)
```

### Attribution
- Mentioned by: @500mk500, @ViriBack, @AndreGironda, @skocherhan
- Hashtags: #Venus #C2 #Dashboard #Panel #ThreatIntelligence
- Community tracking: Active threat intelligence monitoring

---

## YARA Rule

```yara
rule Venus_C2_Panel {
    meta:
        description = "Detects Venus C2 Dashboard"
        author = "C2-Hunting"
        date = "2026-02-17"
        version = "1.0"
    
    strings:
        $s1 = "Venus C2 Dashboard" ascii
        $s2 = "semver 0.5.1" ascii
        $s3 = "Online Agents" ascii
        $s4 = "Data Exfiltration" ascii
        $s5 = "Native Modules (Payloads)" ascii
        $s6 = "Command History" ascii
        $s7 = "Exfiltrated Files" ascii
        $s8 = "Control Panel" ascii
    
    condition:
        4 of them
}
```

---

## Network Signatures (Suricata/Snort)

```
alert http any any -> any any (
    msg:"Venus C2 - Dashboard Access";
    flow:established,to_server;
    content:"Venus C2"; http_header;
    classtype:trojan-activity;
    sid:2000001;
    rev:1;
)

alert http any any -> any any (
    msg:"Venus C2 - Agent Check-in";
    flow:established,to_server;
    content:"POST"; http_method;
    content:"/api/agent/checkin"; http_uri;
    classtype:trojan-activity;
    sid:2000002;
    rev:1;
)

alert http any any -> any any (
    msg:"Venus C2 - File Exfiltration";
    flow:established,to_server;
    content:"POST"; http_method;
    content:"/api/exfil/upload"; http_uri;
    classtype:data-loss;
    sid:2000003;
    rev:1;
)
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| Execution | T1059 | Command and Scripting Interpreter |
| Persistence | T1547 | Boot or Logon Autostart Execution |
| Defense Evasion | T1027 | Obfuscated Files or Information |
| Discovery | T1082 | System Information Discovery |
| Collection | T1113 | Screen Capture |
| Collection | T1005 | Data from Local System |
| Command and Control | T1071.001 | Web Protocols |
| Command and Control | T1573 | Encrypted Channel |
| Exfiltration | T1041 | Exfiltration Over C2 Channel |

---

## Detection Strategies

### Network Level
1. Monitor for connections to `45.8.157.134`
2. Alert on HTTP/HTTPS requests containing "Venus C2" in headers/body
3. Detect agent check-in patterns (periodic beacons)
4. Monitor for large file uploads to suspicious IPs

### Host Level
1. Monitor for process injection
2. Detect in-memory payload execution
3. Alert on suspicious scheduled tasks
4. Monitor registry persistence mechanisms

### Behavioral
1. Detect credential dumping attempts
2. Alert on mass file access patterns
3. Monitor for lateral movement
4. Detect privilege escalation attempts

---

## Threat Hunting Queries

### Network Traffic (Zeek/Bro)
```
# Venus C2 beaconing
conn[id.resp_h] == "45.8.157.134" AND http[method] == "POST"

# Suspicious user agents
http[user_agent] contains "Venus" OR http[user_agent] contains "VenusAgent"

# File exfiltration
http[uri] contains "/api/exfil" OR http[uri] contains "/upload"
```

### Windows Event Logs
```
# Suspicious process creation
EventID: 4688
NewProcessName: *\rundll32.exe OR *\powershell.exe
CommandLine: *-enc* OR *DownloadString* OR *IEX*

# Network connection by suspicious process
EventID: 5156
DestAddress: 45.8.157.134
```

---

## Mitigation

### Prevention
1. Block known C2 IP: `45.8.157.134`
2. Deploy EDR with behavioral detection
3. Implement application whitelisting
4. Restrict PowerShell execution policies
5. Network segmentation

### Detection
1. Deploy IDS/IPS signatures for Venus C2
2. Monitor for "Venus C2" strings in HTTP traffic
3. Alert on connections to known C2 IP
4. Implement YARA scanning on endpoints
5. Monitor for suspicious beaconing patterns

### Response
1. Isolate infected hosts
2. Collect memory dumps for forensics
3. Analyze network traffic for lateral movement
4. Review exfiltrated data scope
5. Force credential rotation
6. Conduct threat hunting for additional compromises

---

## Indicators of Compromise

### Network
```
IP: 45.8.157.134
User-Agent: VenusAgent/* (likely)
Endpoints:
  - /api/agent/checkin
  - /api/agent/register
  - /api/command/queue
  - /api/exfil/upload
  - /dashboard
```

### Host Artifacts
```
File Paths:
  - %TEMP%\venus*.exe
  - %APPDATA%\Venus\
  - C:\ProgramData\Venus\

Registry Keys:
  - HKCU\Software\Venus
  - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\VenusAgent

Services:
  - VenusService (potential service name)
```

---

## Related Tools

Venus C2 shares characteristics with:
- Cobalt Strike
- Metasploit Framework
- Sliver C2
- Covenant C2
- Empire/Starkiller

However, its unique "Native Modules" approach and "semver" versioning distinguish it from mainstream red team tools.

---

## References

- IP Address: 45.8.157.134
- Version: 0.5.1
- Analysis Date: February 2026
- Tracked by: @500mk500, @ViriBack, @AndreGironda, @skocherhan
- Source: OSINT / Threat Intelligence Community

---

*Last Updated: 2026-02-17*
