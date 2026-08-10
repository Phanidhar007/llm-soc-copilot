"""MITRE ATT&CK knowledge base (STIX-style subset).

Bundles a small offline table of ~20 ATT&CK techniques (technique ID, name,
description, detection, response, log keywords, base severity and a coarse
maliciousness label). This acts as the retrieval corpus for the RAG loop and is
a stand-in for a full STIX bundle (``attack.mitrc.org`` publishes the complete
STIX 2.1 JSON). Every entry is intentionally concise so the whole table ships
inside the repo (no network downloads needed).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from typing import List

# STIX-style subset of the MITRE ATT&CK enterprise matrix.
# Fields: id, name, description, detection, response, keywords (log fingerprints
# used to synthesize and retrieve realistic evidence), base_severity (0-3),
# label (coarse adversary intent for triage).
TECHNIQUES: List[dict] = [
    {
        "id": "T1059",
        "signature": "POWERSHELL_SUSPICIOUS",
        "name": "Command and Scripting Interpreter",
        "description": "Adversaries may abuse command and script interpreters (PowerShell, cmd, bash, WMI) to execute commands, scripts or binaries on the victim. Scripts are often combined with obfuscation (T1027) to evade detection.",
        "detection": "Monitor process creation for suspicious invocations of powershell, cmd, bash and script interpreters, especially with encoded or obfuscated arguments.",
        "response": "Kill the offending process tree, review the invoking parent process, and hunt for persistence or lateral movement artifacts created by the script.",
        "keywords": ["powershell", "cmd", "bash", "wscript", "cscript", "scripting", "execute", "-enc", "invoke-expression", "command", "shell"],
        "base_severity": 2,
        "label": "suspicious",
    },
    {
        "id": "T1566",
        "signature": "PHISH_LINK_MATCH",
        "name": "Phishing",
        "description": "Adversaries may send phishing messages to gain initial access to victim systems. Messages often carry malicious attachments or links that lead to credential harvesting or malware delivery.",
        "detection": "Inspect email headers, URLs and attachments for impersonation of trusted domains, known-bad indicators or embedded macro/HTML smuggling content.",
        "response": "Quarantine the message, block the malicious domain/IP, and notify the targeted user to rotate credentials and run a scan.",
        "keywords": ["phish", "phishing", "attachment", "malicious link", "credential harvesting", "mail", "outlook", "smtp", "link", "macro", "office", "docm"],
        "base_severity": 2,
        "label": "suspicious",
    },
    {
        "id": "T1071",
        "signature": "BEACON_HTTP",
        "name": "Application Layer Protocol",
        "description": "Adversaries may communicate using common application-layer protocols such as HTTP/HTTPS to blend with normal traffic while controlling compromised hosts or exfiltrating data.",
        "detection": "Look for long-lived HTTP(S) sessions to low-reputation hosts, irregular User-Agent strings and beacon-like periodic request patterns.",
        "response": "Block the C2 domain/IP at the egress proxy, isolate the host, and review DNS logs for additional resolution patterns.",
        "keywords": ["http", "https", "beacon", "c2", "command and control", "user-agent", "periodic", "callback", "dns", "post", "egress", "traffic"],
        "base_severity": 2,
        "label": "malicious",
    },
    {
        "id": "T1027",
        "signature": "SCRIPT_ENCODED_PAYLOAD",
        "name": "Obfuscated Files or Information",
        "description": "Adversaries may obfuscate commands or data using encoding, compression or encryption to hide malicious content in scripts and payloads from detection.",
        "detection": "Detect unusually large or randomly encoded script blocks, base64-encoded command arguments and suspicious use of compression utilities on endpoints.",
        "response": "Sandbox the artifact, decode the payload, extract indicators and add detections for the decoded command pattern.",
        "keywords": ["obfusc", "base64", "xor", "encoded", "encrypt", "compression", "packed", "decode", "bypass", "payload", "random", "gzip"],
        "base_severity": 2,
        "label": "suspicious",
    },
    {
        "id": "T1136",
        "signature": "NEW_LOCAL_USER",
        "name": "Create Account",
        "description": "Adversaries may create accounts to maintain access to victim systems, often adding privileged accounts to enable further compromise.",
        "detection": "Alert on new user creation events, especially local accounts added outside approved change windows or with suspicious naming patterns.",
        "response": "Disable the unauthorized account, review other recently created accounts and check for logon activity from the new account.",
        "keywords": ["create account", "new user", "net user", "add user", "account creation", "useradd", "adduser", "new administrator", "local account"],
        "base_severity": 1,
        "label": "suspicious",
    },
    {
        "id": "T1548",
        "signature": "ELEVATION_BYPASS",
        "name": "Abuse Elevation Control Mechanism",
        "description": "Adversaries may exploit mechanisms that allow processes to run with higher privileges, bypassing security controls to gain elevated access.",
        "detection": "Monitor for anomalous elevation events such as unexpected setuid binaries, UAC bypasses or services configured to run elevated.",
        "response": "Revoke the privilege, patch the elevation mechanism and investigate the session that triggered the elevation.",
        "keywords": ["sudo", "uac", "setuid", "elevat", "privilege", "runas", "bypass", "escalation", "root", "admin token"],
        "base_severity": 3,
        "label": "malicious",
    },
    {
        "id": "T1041",
        "signature": "EXFIL_C2_LARGE_UPLOAD",
        "name": "Exfiltration Over C2 Channel",
        "description": "Adversaries may steal data and exfiltrate it over an existing command and control channel to avoid creating additional network signatures.",
        "detection": "Correlate large outbound data transfers with active C2 beacons and flag when encrypted tunnels carry unusual data volumes.",
        "response": "Capture network evidence, block the C2 channel and perform a data-loss assessment for the affected asset.",
        "keywords": ["exfil", "c2", "channel", "steal data", "data transfer", "outbound", "tunnel", "exfiltration", "large upload", "upload"],
        "base_severity": 3,
        "label": "malicious",
    },
    {
        "id": "T1210",
        "signature": "REMOTE_EXPLOIT_HANDSHAKE",
        "name": "Exploitation of Remote Services",
        "description": "Adversaries may exploit remote services such as RDP, SSH or SMB to gain unauthorized access to other systems on the network.",
        "detection": "Detect exploit signatures in traffic and endpoint logs, including unusual RDP/SMB sessions and known-vulnerable protocol handshakes.",
        "response": "Isolate the affected hosts, patch the vulnerable service and scan the segment for signs of the same exploit.",
        "keywords": ["exploit", "rdp", "smb", "ssh", "vulnerable", "handshake", "shell", "eternalblue", "bluekeep", "remote exploit", "cve"],
        "base_severity": 3,
        "label": "malicious",
    },
    {
        "id": "T1486",
        "signature": "RANSOMWARE_FILE_OVERWRITE",
        "name": "Data Encrypted for Impact",
        "description": "Adversaries may encrypt files on a host or network share to disrupt availability and pressure victims, typically as ransomware.",
        "detection": "Alert on mass file modification with new extensions, rapid overwrite patterns and ransomware notes appearing on shares.",
        "response": "Disconnect affected hosts, preserve the encryption process sample and restore from verified backups while notifying incident response.",
        "keywords": ["ransomware", "encrypt", "encrypted files", "new extension", "file overwrite", "bitlocker", "mass file", "locker", "extortion", "decryption note"],
        "base_severity": 3,
        "label": "malicious",
    },
    {
        "id": "T1005",
        "signature": "LOCAL_DATA_COLLECTION",
        "name": "Data from Local System",
        "description": "Adversaries may search and collect data from local system sources such as browser caches, configuration files and sensitive documents before exfiltration.",
        "detection": "Watch for suspicious reads of credential files, document directories and browser data by unusual processes.",
        "response": "Identify the collecting process, preserve the files it touched and scope how much data was gathered.",
        "keywords": ["collect", "local data", "browser cache", "documents", "credentials file", "gather", "config file", "steal files", "sensitive data"],
        "base_severity": 2,
        "label": "malicious",
    },
    {
        "id": "T1567",
        "signature": "WEB_SERVICE_UPLOAD",
        "name": "Exfiltration Over Web Service",
        "description": "Adversaries may exfiltrate data over web services such as paste sites, file hosting or collaboration tools to blend with legitimate traffic.",
        "detection": "Monitor outbound traffic to file-sharing and paste services, especially from hosts that rarely use them.",
        "response": "Block the web-service domain for the affected account, review upload events and contain the exfiltrating host.",
        "keywords": ["exfil", "web service", "pastebin", "file hosting", "upload", "dropbox", "gist", "share", "cloud upload", "exfiltration"],
        "base_severity": 3,
        "label": "malicious",
    },
    {
        "id": "T1083",
        "signature": "DIR_ENUMERATION",
        "name": "File and Directory Discovery",
        "description": "Adversaries may enumerate files and directories to understand the layout of a victim environment and locate valuable targets.",
        "detection": "Detect anomalous recursive listing of shared drives, network shares or large directory trees by non-interactive processes.",
        "response": "Note the discovering process, monitor for follow-on collection activity and review access to the enumerated shares.",
        "keywords": ["discovery", "enumerate", "dir", "ls", "find", "list files", "directory", "share enumeration", "walk", "search files"],
        "base_severity": 1,
        "label": "suspicious",
    },
    {
        "id": "T1021",
        "signature": "REMOTE_SERVICE_LOGIN",
        "name": "Remote Services",
        "description": "Adversaries may use valid credentials to access remote services such as WinRM, PSExec, VNC or RDP to move laterally.",
        "detection": "Alert on first-time or cross-domain remote service sessions and on the use of admin shares or remote management tools.",
        "response": "Validate the sessions against approved administrative workflow, rotate the credentials used and contain unauthorized access.",
        "keywords": ["psexec", "winrm", "vnc", "rdp login", "remote", "lateral", "admin share", "wmi", "remote session", "mmc"],
        "base_severity": 2,
        "label": "malicious",
    },
    {
        "id": "T1572",
        "signature": "PROTOCOL_TUNNEL",
        "name": "Protocol Tunneling",
        "description": "Adversaries may tunnel network communications through a proxy or encapsulated protocol to bypass network defenses.",
        "detection": "Look for unexpected SSH tunnels, encrypted proxy software and unusual traffic encapsulated inside allowed protocols.",
        "response": "Terminate the tunnel, inspect the endpoints involved and block the tunneling utility or port.",
        "keywords": ["tunnel", "ssh tunnel", "proxy", "port forward", "encapsulate", "socks", "encrypted proxy", "tunneling", "tcp forward", "reverse tunnel"],
        "base_severity": 3,
        "label": "malicious",
    },
    {
        "id": "T1003",
        "signature": "CREDENTIAL_DUMP_LSASS",
        "name": "OS Credential Dumping",
        "description": "Adversaries may dump credentials from the operating system or memory to obtain password hashes and plaintext secrets for lateral movement.",
        "detection": "Detect access to LSASS memory, the SAM registry hive or NTDS.dit, and the presence of credential-dumping tooling.",
        "response": "Isolate the host, reset affected account credentials and investigate which accounts were captured.",
        "keywords": ["lsass", "mimikatz", "sam dump", "ntds", "credential dump", "password hash", "dump", "sekurlsa", "registry", "wdigest"],
        "base_severity": 3,
        "label": "malicious",
    },
    {
        "id": "T1110",
        "signature": "AUTH_FAILURE_STORM",
        "name": "Brute Force",
        "description": "Adversaries may use brute force or password spraying to gain access to accounts when password policy or lockout thresholds are weak.",
        "detection": "Flag high volumes of failed logons against a single account or source IP, and distributed sprays across many accounts.",
        "response": "Temporarily block the source, require MFA or password resets for targeted accounts and review logon patterns for successful hits.",
        "keywords": ["brute force", "failed logon", "password spray", "login attempt", "many attempts", "auth failure", "credential guessing", "lockout", "kerberos"],
        "base_severity": 2,
        "label": "suspicious",
    },
    {
        "id": "T1098",
        "signature": "ACCOUNT_GROUP_MOD",
        "name": "Account Manipulation",
        "description": "Adversaries may manipulate accounts to maintain access, such as adding credentials, modifying group memberships or enabling persistence.",
        "detection": "Monitor group membership changes, password resets and modifications to privileged accounts.",
        "response": "Revert the account change, audit other accounts modified by the same session and strengthen change monitoring.",
        "keywords": ["account manipulation", "add to group", "group membership", "modify account", "password reset", "admin group", "persistence", "modify user", "member add"],
        "base_severity": 2,
        "label": "malicious",
    },
    {
        "id": "T1557",
        "signature": "ARP_SPOOF_DETECTED",
        "name": "Adversary-in-the-Middle",
        "description": "Adversaries may position themselves between two communicating parties to intercept or modify traffic, often via ARP/DNS spoofing.",
        "detection": "Detect ARP cache poisoning, unexpected DHCP or proxy settings and TLS certificates that do not match the expected issuer.",
        "response": "Segment the network, verify switches/APs and require certificate pinning or endpoint detection on clients.",
        "keywords": ["arp spoof", "mitm", "dhcp poisoning", "proxy", "tls cert", "man in the middle", "spoof", "gateway", "ip forwarding", "redirect"],
        "base_severity": 3,
        "label": "malicious",
    },
    {
        "id": "T1622",
        "signature": "DEBUGGER_EVASION",
        "name": "Debugger Evasion",
        "description": "Adversaries may employ anti-debugging checks to evade automated analysis and slow defenders who try to inspect malware.",
        "detection": "Detect process queries for debugging APIs, timing checks and suspicious environment checks by malware-like processes.",
        "response": "Run the sample under a full sandbox, patch or skip the evasion check and extract behavior after the anti-debug logic.",
        "keywords": ["debug", "anti-debug", "debugger", "timing check", "evasion", "isdbg", "analysis", "sandbox", "ptrace", "detect debug"],
        "base_severity": 1,
        "label": "suspicious",
    },
    {
        "id": "T1614",
        "signature": "GEO_QUERY",
        "name": "System Location Discovery",
        "description": "Adversaries may gather information about a victim's location such as country, timezone or language to tailor operations.",
        "detection": "Alert on unexpected geolocation or timezone queries from compromised endpoints.",
        "response": "Correlate the endpoint with threat-intel feeds and review other telemetry from the same session.",
        "keywords": ["geoloc", "timezone", "country", "location discovery", "language", "geo ip", "region", "system location", "detect location", "geo"],
        "base_severity": 1,
        "label": "suspicious",
    },
]

_INDEX = {t["id"]: t for t in TECHNIQUES}


@dataclass
class Technique:
    """A single MITRE ATT&CK technique row."""

    id: str
    name: str
    description: str
    detection: str
    response: str
    signature: str
    keywords: List[str]
    base_severity: int
    label: str

    @property
    def corpus_doc(self) -> str:
        """Document used for TF-IDF retrieval (technique text + fingerprints).

        The signature name is deliberately excluded: in production the alert's
        signature ID is already mapped by detection engineering, so leaving it
        out makes retrieval reflect real "free-text -> technique" reasoning.
        """
        return " ".join(
            [self.id, self.name, self.description, self.detection, self.response]
            + list(self.keywords)
        )

    def to_dict(self) -> dict:
        return asdict(self)


def load_techniques() -> List[Technique]:
    """Load the bundled technique table as Technique objects."""
    return [Technique(**t) for t in TECHNIQUES]


def get_technique(technique_id: str) -> Technique:
    """Return a Technique by ID (raises KeyError if unknown)."""
    return Technique(**_INDEX[technique_id])


def severity_name(level: int) -> str:
    """Map a 0-3 severity integer to a human-readable label."""
    return ["low", "medium", "high", "critical"][int(level) % 4]


def dump_knowledge(path: str) -> None:
    """Persist the technique table as JSON (for external tools/inspection)."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(TECHNIQUES, fh, indent=2)
