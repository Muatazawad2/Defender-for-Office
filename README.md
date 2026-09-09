# Defender for Office

Tools and scripts for **Microsoft Defender for Office 365**.

Each folder covers one area of the product and is self-contained — the script, its documentation, and screenshots live together.

---

## Contents

### [Attack Simulator](./Attack%20Simulator)

Tooling for **Attack simulation training**.

| Script | Purpose |
|---|---|
| [`Get-AttackSimRepeatOffenders.ps1`](./Attack%20Simulator/Get-AttackSimRepeatOffenders.ps1) | Build a repeat-offender list using **your own** definition — link clicks in a rolling window — rather than the built-in rule, which only counts credential compromise in consecutive simulations and has no time window. |

---

## Requirements

Most tooling here assumes:

- Microsoft Defender for Office 365 **Plan 2**, or **Microsoft 365 E5**
- PowerShell 7
- `Microsoft.Graph.Authentication` module

Individual folders list their own specific Graph scopes and Entra roles.

---

## Author

**Dr. Muataz Awad**
Principal Cloud Solution Architect — Security

---

## Disclaimer

Provided as-is, with no warranty. Not an official Microsoft product. Test in a non-production tenant first.
