# SigmaVault

I provided AI some of the attack scenarios and TTPs I had seen and stopped during my SOC experience, and asked it to generate sigma rules from it.
I haven't tested them yet, but may take this project further to more scenarios and Linux.

If you like what you see, or got any ideas to improve, let me know. Hope it helps.

-------------------------------------



# Windows Sigma Detection Rules

A collection of Sigma rules designed to detect suspicious Windows activity involving Microsoft Office, scripting, security-control modification, and Internet bandwidth-sharing applications.

These detections are primarily intended for **Windows endpoint telemetry**, especially Sysmon/EDR process, file, and registry events.

---

## 1. Microsoft Office Application Creates VBScript

### Rule

`Microsoft Office Application Creates VBScript File`

### Purpose

Detects Microsoft Office applications creating VBScript or VBScript-encoded files.

Office applications such as Word, Excel, PowerPoint, Outlook, Access, Publisher, and OneNote can be abused to execute or drop malicious scripts through weaponized documents, macros, or other document-based techniques.

The creation of `.vbs` or `.vbe` files by an Office process is therefore considered suspicious and should be investigated.

### Detection Logic

The rule looks for:

* A Microsoft Office application as the creating process.
* Creation of a file ending in:

  * `.vbs`
  * `.vbe`

Example process relationship:

```text
WINWORD.EXE
    └── creates
        └── malicious.vbs
```

### Relevant Telemetry

Recommended telemetry:

* **Sysmon Event ID 11 — FileCreate**
* EDR file creation telemetry

Important fields:

```text
Image
TargetFilename
```

### MITRE ATT&CK

* **T1059.005 — Command and Scripting Interpreter: Visual Basic**
* **T1204.002 — User Execution: Malicious File**

### Severity

**High**

Office applications normally have little reason to generate executable VBScript files in ordinary user workflows.

### False Positives

Possible legitimate activity includes:

* Office automation
* Enterprise deployment scripts
* Administrative workflows
* Legacy business applications
* Security testing

### Investigation

When triggered, investigate:

1. Which Office document caused the activity?
2. Where was the `.vbs` file created?
3. Was the file created in `%TEMP%`, `%APPDATA%`, or another user-writable directory?
4. Was `wscript.exe` or `cscript.exe` subsequently executed?
5. Did the script create additional files or processes?
6. Was PowerShell subsequently launched?

A particularly suspicious chain is:

```text
WINWORD.EXE
    ↓
malicious.vbs
    ↓
wscript.exe
    ↓
powershell.exe
    ↓
network connection
```

---

# 2. Microsoft Office Application Spawns PowerShell

### Rule

`Microsoft Office Application Spawns PowerShell`

### Purpose

Detects Microsoft Office applications directly spawning PowerShell or PowerShell Core.

Malicious Office documents can abuse macros, DDE, exploits, or other execution mechanisms to launch PowerShell.

An Office → PowerShell parent-child relationship is therefore a valuable behavioral indicator.

### Detection Logic

The rule identifies:

**Parent process:**

```text
WINWORD.EXE
EXCEL.EXE
POWERPNT.EXE
OUTLOOK.EXE
MSACCESS.EXE
MSPUB.EXE
ONENOTE.EXE
```

**Child process:**

```text
powershell.exe
pwsh.exe
```

Example:

```text
WINWORD.EXE
    └── powershell.exe
```

### Relevant Telemetry

Recommended telemetry:

* Sysmon Event ID 1 — Process Creation
* EDR process telemetry

Important fields:

```text
Image
ParentImage
CommandLine
```

### MITRE ATT&CK

* **T1059.001 — Command and Scripting Interpreter: PowerShell**

### Severity

**High**

PowerShell itself is legitimate and widely used, but Office applications spawning PowerShell is an uncommon and potentially dangerous process relationship.

### False Positives

Possible legitimate activity includes:

* Enterprise Office automation
* IT administration
* Security tooling
* Office plugins
* Automated document-processing systems

### Investigation

Examine the PowerShell command line.

Particularly suspicious indicators include:

```text
-EncodedCommand
-IEX
Invoke-Expression
Invoke-WebRequest
WebClient
DownloadString
DownloadFile
FromBase64String
```

Also investigate whether PowerShell:

* Downloaded files
* Created persistence
* Modified the registry
* Disabled security controls
* Spawned additional processes

A high-confidence chain could look like:

```text
WINWORD.EXE
    ↓
powershell.exe
    ↓
Download
    ↓
Execution
```

---

# 3. Internet Bandwidth-Sharing Application Detected

### Rule

`Internet Bandwidth Sharing Application Detected`

### Purpose

Detects known applications that allow users to monetize or share unused Internet bandwidth.

Examples include:

* Honeygain
* EarnApp
* Pawns.app
* TraffMonetizer
* Peer2Profit
* PacketStream

These applications are not automatically malicious. However, they can consume network bandwidth, establish persistent outbound connections, and introduce software that may be undesirable in enterprise environments.

Some bandwidth-sharing applications are also classified as potentially unwanted applications by security vendors.

### Detection Logic

The rule identifies known executable filenames associated with bandwidth-sharing applications.

Example:

```text
Honeygain.exe
earnapp.exe
Pawns.app.exe
Traffmonetizer.exe
Peer2Profit.exe
packetstream.exe
```

### Relevant Telemetry

Recommended telemetry:

* Sysmon Event ID 1 — Process Creation
* EDR process telemetry
* Application inventory
* Network telemetry

Important fields:

```text
Image
CommandLine
OriginalFileName
Company
Hashes
Signer
```

### MITRE ATT&CK

This detection is primarily a **software/policy detection** rather than a direct ATT&CK technique.

Potentially relevant techniques may include:

* **T1090 — Proxy**
* **T1105 — Ingress Tool Transfer**
* Persistence techniques depending on the application's behavior

### Severity

**Medium**

The presence of a bandwidth-sharing application does not necessarily indicate compromise.

This detection is particularly useful for:

* Corporate environments
* SOC monitoring
* Software policy enforcement
* BYOD monitoring
* PUA detection

### False Positives

Possible legitimate activity includes:

* Authorized bandwidth-sharing software
* Personal devices
* Security research
* Testing environments

### Investigation

Do not rely solely on the executable filename.

Investigate:

1. File hash
2. Digital signature
3. Publisher
4. Installation path
5. Parent process
6. Persistence mechanisms
7. Network destinations
8. Firewall modifications
9. User who installed the application

A renamed malicious executable can bypass filename-based detection.

Therefore, production implementations should combine:

```text
Process Name
+
OriginalFileName
+
Publisher
+
Digital Signature
+
Hash
+
Network Behavior
```

### Recommended Enhancement

Create a secondary detection for bandwidth-sharing applications that:

* Create persistence
* Modify firewall rules
* Run from `%TEMP%` or unusual `%APPDATA%` locations
* Make persistent outbound connections
* Run under unexpected accounts

---

# 4. UAC Disabled Through Registry

### Rule

`UAC Disabled Through Registry`

### Purpose

Detects attempts to disable Windows User Account Control by modifying the `EnableLUA` registry value.

UAC is an important Windows security mechanism that helps prevent unauthorized elevation of privileges.

An attacker with sufficient privileges may attempt to disable UAC to make subsequent privilege escalation or execution easier.

### Detection Logic

The rule monitors:

```text
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA
```

The detection specifically looks for the value being changed to:

```text
0
```

Example:

```text
EnableLUA = 0
```

### Relevant Telemetry

Recommended telemetry:

* Sysmon registry events
* EDR registry telemetry
* Windows registry auditing

Important fields:

```text
TargetObject
Details
```

### MITRE ATT&CK

* **T1548.002 — Abuse Elevation Control Mechanism: Bypass User Account Control**
* **T1112 — Modify Registry**

### Severity

**High**

Disabling UAC reduces an important Windows security boundary and can indicate defense evasion or preparation for further compromise.

### False Positives

Possible legitimate activity includes:

* Windows deployment
* Enterprise imaging
* System configuration
* Administrative troubleshooting
* Security testing

### Investigation

When triggered, determine:

1. Which process modified `EnableLUA`?
2. Which user performed the modification?
3. Was the process elevated?
4. Were other security settings modified?
5. Did the modification occur shortly before suspicious process execution?

A suspicious sequence could be:

```text
powershell.exe
    ↓
EnableLUA = 0
    ↓
security configuration changes
    ↓
malware execution
```

---

# 5. Microsoft Defender Disabled Through Registry

### Rule

`Microsoft Defender Security Settings Disabled Through Registry`

### Purpose

Detects registry modifications intended to disable or weaken Microsoft Defender Antivirus protections.

Attackers frequently attempt to weaken endpoint security before executing malware or performing post-exploitation activity.

The rule monitors several Defender-related registry settings rather than relying on a single value.

### Detection Logic

The rule monitors Defender policy locations including:

```text
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\
```

and:

```text
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\
```

Examples include:

```text
DisableAntiSpyware
DisableAntiVirus
DisableRealtimeMonitoring
DisableBehaviorMonitoring
DisableOnAccessProtection
DisableScanOnRealtimeEnable
```

The detection focuses on settings being enabled in a way that disables or weakens protection.

Example:

```text
DisableRealtimeMonitoring = 1
```

### Relevant Telemetry

Recommended telemetry:

* Sysmon registry events
* EDR registry telemetry
* Windows registry auditing

Important fields:

```text
TargetObject
Details
```

### MITRE ATT&CK

* **T1562.001 — Impair Defenses: Disable or Modify Tools**
* **T1112 — Modify Registry**

### Severity

**High**

Modifying Defender configuration to weaken security controls is strongly associated with defense evasion.

### False Positives

Possible legitimate activity includes:

* Enterprise Group Policy
* Endpoint management systems
* Defender configuration scripts
* Security testing
* Troubleshooting
* Authorized security products

### Investigation

Identify:

1. The process responsible for the registry change.
2. The user/account performing the change.
3. Whether the machine is managed by Group Policy.
4. Whether additional Defender settings changed.
5. Whether PowerShell was involved.
6. Whether suspicious processes executed afterward.

A particularly suspicious sequence is:

```text
powershell.exe
    ↓
Defender registry modification
    ↓
Defender protection weakened
    ↓
malware execution
```

---

# 6. Microsoft Defender Disabled Through PowerShell

### Rule

`Microsoft Defender Disabled Through PowerShell`

### Purpose

Detects attempts to disable or weaken Microsoft Defender using PowerShell cmdlets.

This complements the registry-based Defender detection because Defender can be modified through PowerShell without the specific registry event being the most useful indicator.

### Detection Logic

The rule monitors PowerShell commands containing:

```text
Set-MpPreference
Add-MpPreference
```

combined with Defender configuration options such as:

```text
DisableRealtimeMonitoring
DisableBehaviorMonitoring
DisableIOAVProtection
DisableScriptScanning
DisableArchiveScanning
DisableIntrusionPreventionSystem
DisableBlockAtFirstSeen
```

and values indicating that the setting is being enabled for disabling protection.

Example:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

### Relevant Telemetry

Recommended telemetry:

* Sysmon Event ID 1
* PowerShell Script Block Logging
* PowerShell operational logs
* EDR telemetry

Important fields:

```text
Image
CommandLine
ParentImage
ScriptBlockText
```

### MITRE ATT&CK

* **T1562.001 — Impair Defenses: Disable or Modify Tools**

### Severity

**High**

Attempts to disable real-time protection or other Defender components should generally receive high priority in a SOC.

### False Positives

Possible legitimate activity includes:

* Endpoint configuration
* Group Policy automation
* Security testing
* Malware-analysis labs
* IT administration
* Defender troubleshooting

### Investigation

Investigate:

1. Parent process
2. User account
3. PowerShell command line
4. Script block contents
5. Whether PowerShell was encoded
6. Processes executed immediately afterward
7. Network activity following the change

Particularly suspicious:

```text
WINWORD.EXE
    ↓
powershell.exe
    ↓
Set-MpPreference
    ↓
DisableRealtimeMonitoring
    ↓
malware execution
```

---

# Detection Correlation

Individual detections are useful, but combining multiple signals can significantly increase confidence.

## Example High-Confidence Attack Chain

```text
Office document
      │
      ▼
WINWORD.EXE
      │
      ├──────────────► creates .VBS
      │
      ▼
powershell.exe
      │
      ├──────────────► disables Defender
      │
      ├──────────────► modifies UAC
      │
      ▼
Payload execution
```

This should receive considerably higher priority than any individual event.

## Recommended Correlation

Consider correlating:

```text
Office → VBScript creation
        +
Office → PowerShell
```

or:

```text
PowerShell
    +
Defender modification
```

or:

```text
UAC modification
    +
Defender modification
    +
new process execution
```

The combination of **Office spawning PowerShell + script creation + security-control modification** is especially valuable for identifying malicious document-based execution.

---

# Telemetry Requirements

| Detection                        | Sysmon / EDR Telemetry         |
| -------------------------------- | ------------------------------ |
| Office → VBS                     | FileCreate / File telemetry    |
| Office → PowerShell              | Process Creation               |
| Bandwidth-sharing apps           | Process + Network telemetry    |
| UAC modification                 | Registry telemetry             |
| Defender registry modification   | Registry telemetry             |
| Defender PowerShell modification | Process + PowerShell telemetry |

For a stronger implementation, collect:

```text
Process Image
Parent Image
CommandLine
User
Integrity Level
TargetFilename
TargetObject
Registry Details
File Hash
Digital Signature
Network Connections
```

---

# Recommended Severity Model

| Detection                            | Default Severity |
| ------------------------------------ | ---------------: |
| Office creates VBS/VBE               |             High |
| Office spawns PowerShell             |             High |
| Bandwidth-sharing application        |           Medium |
| UAC disabled through registry        |             High |
| Defender disabled through registry   |             High |
| Defender disabled through PowerShell |             High |

Severity should ultimately be adjusted according to the organization's normal baseline and approved software/configuration.

---

# Important Implementation Note

These rules are designed around **behavior and Windows telemetry**, not around a particular SIEM vendor.

Before deploying them to production, field names should be mapped to the target SIEM's schema.

For example:

```text
Sigma
  ↓
Sysmon / Windows Event
  ↓
Elastic ECS / Splunk CIM / Sentinel ASIM
  ↓
SIEM detection
  ↓
Correlation
  ↓
SOC alert
```

The strongest implementation combines **process ancestry, command line, registry changes, file creation, signatures/hashes, and network telemetry** rather than relying on a single indicator.

