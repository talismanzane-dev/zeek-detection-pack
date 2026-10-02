# MITRE ATT&CK mapping

Every `Detection` carries a `technique_id` and `tactic`. The values below are
what the analyzers emit; secondary techniques appear in
`evidence.secondary_techniques`. Mappings follow ATT&CK Enterprise.

## Summary

| Detector | Technique ID | Technique | Tactic | One-line rationale |
|---|---|---|---|---|
| `c2_beaconing` | **T1071** | Application Layer Protocol | Command and Control (TA0011) | Periodic, size-consistent outbound sessions to one destination are the network artifact of implant check-ins. |
| `c2_beaconing` | T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | Refinement when Zeek's `service` is `http`/`ssl`/`quic`. |
| `c2_beaconing` | T1071.004 | Application Layer Protocol: DNS | Command and Control | Refinement when the beaconing flow's `service` is `dns`. |
| `c2_beaconing` | **T1095** | Non-Application Layer Protocol | Command and Control | Used when the beaconing flow is ICMP (no application layer). |
| `dns_tunneling` | **T1071.004** | Application Layer Protocol: DNS | Command and Control | Encoded payload in query names and TXT/NULL answers carries C2 over permitted port 53. |
| `dns_tunneling` | T1048.003 *(secondary)* | Exfiltration Over Unencrypted Non-C2 Protocol | Exfiltration (TA0010) | Added when the unique-subdomain and volume components both saturate — the traffic is shaped like bulk data leaving. |
| `dga` | **T1568.002** | Dynamic Resolution: Domain Generation Algorithms | Command and Control | NXDOMAIN bursts of lexically random names are malware iterating a DGA to find its live C2. |
| `lateral_movement` | **T1021.002** | Remote Services: SMB/Windows Admin Shares | Lateral Movement (TA0008) | New SMB (445/139) admin sessions and writes to `ADMIN$`/`C$` are the footprint of remote execution (PsExec, `sc`, WMI staging). |
| `lateral_movement` | T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement | New internal pair on 3389. |
| `lateral_movement` | T1021.003 | Remote Services: Distributed Component Object Model | Lateral Movement | New internal pair on 135 (RPC endpoint mapper used by DCOM/WMI). |
| `lateral_movement` | T1021.004 | Remote Services: SSH | Lateral Movement | New internal pair on 22. |
| `lateral_movement` | T1021.006 | Remote Services: Windows Remote Management | Lateral Movement | New internal pair on 5985/5986. |
| `lateral_movement` | T1570 *(secondary)* | Lateral Tool Transfer | Lateral Movement | Added when an executable or script is written to / opened on an admin share. |
| `lateral_movement` | **T1046** | Network Service Discovery | Discovery (TA0007) | Admin-port fan-out where most attempts fail (`pattern: scan`); reported at one severity band lower. |

## Related techniques that are *not* claimed

| Technique | Why it is not emitted |
|---|---|
| T1550 / T1550.002 Use Alternate Authentication Material: Pass the Hash | Often accompanies the lateral-movement activity above, but proving alternate credential material needs authentication telemetry (`ntlm.log`, `kerberos.log`, endpoint logs). The analyzers do not consume those logs, so they never claim T1550. This is a candidate v2 enrichment. |
| T1572 Protocol Tunneling | DNS tunneling is mapped to T1071.004 (C2 over DNS) as in the design spec; organisations that track tunnelling separately can add T1572 in their SIEM mapping. |
| T1573 Encrypted Channel | Beaconing over TLS is reported as T1071.001; the analyzer does not inspect encryption. |

## Where the mapping lives in code

- `zdp/analyzers/c2_beaconing.py` → `_technique()`
- `zdp/analyzers/dns_tunneling.py` → `TECHNIQUE`, `EXFIL_TECHNIQUE`
- `zdp/analyzers/dga.py` → `TECHNIQUE`
- `zdp/analyzers/lateral_movement.py` → `PORT_TECHNIQUES`, `SMB_TECHNIQUE`, `SCAN_TECHNIQUE`

Exported Sigma rules carry the same techniques as `attack.tXXXX` tags and
Suricata rules carry `mitre_technique_id` / `mitre_tactic_id` metadata.
