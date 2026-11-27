# Attack-vs-Defense Coverage Matrix

Instead of organizing tools for offensive execution, **`raksa`** maps common attacker techniques across reconnaissance, initial access, execution, persistence, supply-chain compromise, and denial of service directly to **defensive sensors, verification playbooks, and MITRE D3FEND controls** (`raksa attack-matrix`).

## Coverage Summary (`v0.1.0` Baseline + `v0.4.0` Planned Closures)

| Threat Category | MITRE ATT&CK | MITRE D3FEND | Defending Layer(s) | Status | Verification Command |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Reconnaissance & Port Scanning | `T1046` | `D3-NTA` | `netguard`, `siem` | `covered` | `raksa scan --layers netguard,siem` |
| SQLi & Command Injection | `T1190 / T1059` | `D3-ITF` | `webshield`, `siem` | `covered` | `raksa-webshield inspect-request` |
| XSS, CSRF, Clickjacking & Sessions | `T1059.007 / T1185` | `D3-SRA` | `webshield` | `covered` | `raksa scan --profile web --path .` |
| SSH Brute Force & Credential Stuffing | `T1110` | `D3-LAM` | `hostguard`, `siem` | `covered` | `raksa scan --profile host` |
| PrivEsc & Host Persistence Hooks | `T1543 / T1053 / T1548` | `D3-FIM` | `hostguard`, `iocscan` | `covered` | `raksa playbooks run --name host-hardening-audit` |
| Malware Payloads, RATs & Loaders | `T1204 / T1027` | `D3-FA` | `iocscan`, `siem` | `covered` | `raksa playbooks run --name incident-triage` |
| Malicious Docs & Archive Bombs | `T1566.001 / T1204.002` | `D3-DA` | `iocscan` | `covered` | `raksa-iocscan scan --path ./uploads` |
| Secret Leaks & KEV/EPSS CVEs | `T1552 / T1195` | `D3-SYSV` | `pipeguard` | `covered` | `raksa playbooks run --name pre-release-gate` |
| Container Breakout & CI/CD Poisoning | `T1611 / T1525` | `D3-CISC` | `hostguard`, `pipeguard` | `covered` | `raksa scan --profile repo --path .` |
| Multi-Stage Chains & Log Tampering | `T1070 / T1078` | `D3-AL` | `siem`, `hostguard` | `covered` | `raksa posture --verify` |
| DoS / SYN & Slowloris Readiness | `T1498 / T1499` | `D3-ITF` | `netguard`, `hostguard`, `webshield` | `partial` | `raksa playbooks run --name ddos-readiness` |
| C2 Beaconing & DNS Tunneling | `T1071.004 / T1573` | `D3-DNSAL` | `netguard`, `siem` | `partial` | `raksa-siem analyze <logs> --output html` |
| Phishing & Domain DNS/DMARC Posture | `T1566 / T1583` | `D3-DNSDL` | `orchestrator`, `webshield` | `planned` | Planned `v0.4.0` read-only DNS/SPF/DMARC audit |
| Windows/AD & macOS Host Checks | `T1087 / T1558` | `D3-HDA` | `hostguard`, `netguard` | `planned` | Planned `v0.4.0` cross-OS host auditors |
| OpenAPI / GraphQL & Smuggling Guards | `T1190` | `D3-SVA` | `webshield` | `planned` | Planned `v0.4.0` API schema & CL.TE checks |
| Terraform Plan JSON & Cosign VEX | `T1195.002` | `D3-SYSV` | `pipeguard` | `planned` | Planned `v0.4.0` `PIPE-107` & plan graph |
