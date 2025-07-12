
# Enterprise gMSA/MSA Security Audit Tool

This is an advanced PowerShell tool that audits gMSA/MSA accounts in Active Directory environments.  
It enumerates managed service accounts, detects suspicious permissions, audits ACLs, correlates event logs, and generates a full HTML dashboard & reports.

---

##  Features

- Enumerates gMSA/MSA accounts with security principals.
- Detects suspicious / over-permissive assignments (like Authenticated Users).
- Checks ACLs on accounts & OUs for risky ACEs.
- Correlates security events (4624 logon, 4672 elevation) to track usage.
- Outputs:
    - `gMSA_Accounts.csv` — accounts & principals
    - `ACL_Violations.json` — risky ACEs
    - `EventLog_Usage.csv` — logon & elevation events
    - `Dashboard.html` — interactive dashboard
    - `Audit_Summary.txt` — summary report

---

##  Requirements

Before you can run this tool, **make sure your environment is ready:**

 **Windows OS** (10, 11, or Windows Server).

 **PowerShell 5.1+**  
Check with:
```powershell
$PSVersionTable.PSVersion
```

 **RSAT Active Directory module installed.**  
This provides cmdlets like `Get-ADObject`.

###  How to install RSAT:

For Windows 10/11:
```powershell
Get-WindowsCapability -Name RSAT.ActiveDirectory* -Online
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

For Windows Server:
```powershell
Install-WindowsFeature RSAT-AD-PowerShell
```

 **Your machine must be domain-joined** (or at least connected to the domain you’re auditing).

 **Your user must have permissions to:**
- Query Active Directory (`Get-ADObject`)
- Read ACLs on AD objects
- Read Security Event Logs (`Get-WinEvent -LogName Security`)

---

##  Usage

###  Running the tool

1. Copy `ADGuardGMSA.ps1` to your working directory.

2. Open **PowerShell as Administrator**.

3. Run the script:

```powershell
.\ADGuardGMSA.ps1
```

By default it will analyze the last **30 days** of security events.

###  Change the number of days

```powershell
.\ADGuardGMSA.ps1 -EventLogDays 60
```

---

##  Output files

After running, you’ll find:

```
📂 YourFolder/
├── gMSA_Accounts.csv
├── ACL_Violations.json
├── EventLog_Usage.csv
├── Dashboard.html
└── Audit_Summary.txt
```

- Open `Dashboard.html` in your browser for a rich interactive overview.
- See `Audit_Summary.txt` for a quick text summary.

---

## 🤝 Contributing

We welcome contributions to improve or extend this tool!

- Found a bug? Open an Issue.
- Want to add more features (like additional event IDs or SIEM output)? Create a PR.
- Please follow clean PowerShell style and include comments.

---

## ⚖ Disclaimer

> ⚠ **DISCLAIMER:**  
> This script is provided "as is" for security auditing and hardening purposes.  
> Use it **only on systems you own or have explicit authorization to test.**  
>  
> We accept **no liability for any misuse or damage** caused by improper use of this tool.

---

## ❤️ Authors & Credits

Built with ❤️ by testone5iix and contributors.

---

**Enjoy securing your AD environment!**
