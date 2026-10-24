"""String intelligence: stable IDs, IOC/entity extraction and behavior tags.

The functions here are deliberately conservative.  A tag is a hint for an
analyst or an AI agent, not a verdict.  Everything is derived from the recovered
plaintext alone, so it can run without IDA and without network access.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Iterable

# Tag metadata is also exposed as an MCP resource, so keep descriptions short
# and machine-readable.
TAG_DEFINITIONS: dict[str, dict[str, str]] = {
    # Content tags.
    "url": {"category": "content", "severity": "info", "description": "HTTP/FTP URL or defanged variant."},
    "domain": {"category": "content", "severity": "info", "description": "DNS domain name."},
    "ip": {"category": "content", "severity": "info", "description": "IPv4 address, optionally with a port."},
    "email": {"category": "content", "severity": "info", "description": "Email address."},
    "path": {"category": "content", "severity": "info", "description": "Windows, UNC or Unix filesystem path."},
    "registry": {"category": "content", "severity": "info", "description": "Windows registry key."},
    "wallet": {"category": "content", "severity": "info", "description": "Cryptocurrency wallet-like address."},
    "hash": {"category": "content", "severity": "info", "description": "MD5/SHA1/SHA256 hex digest."},
    "filename": {"category": "content", "severity": "info", "description": "Filename with a known extension."},
    "user_agent": {"category": "content", "severity": "info", "description": "HTTP User-Agent value."},
    "jwt": {"category": "content", "severity": "info", "description": "JSON Web Token."},
    "environment": {"category": "content", "severity": "info", "description": "Environment variable reference."},
    "named_pipe": {"category": "content", "severity": "info", "description": "Windows named pipe path."},
    # Behavior tags.
    "network": {"category": "behavior", "severity": "low", "description": "Networking APIs or network indicators."},
    "http": {"category": "behavior", "severity": "low", "description": "HTTP URL, verb, header or user agent."},
    "dns": {"category": "behavior", "severity": "low", "description": "DNS resolution or domain usage."},
    "download": {"category": "behavior", "severity": "medium", "description": "Download or remote-fetch capability."},
    "execution": {"category": "behavior", "severity": "medium", "description": "Process or command execution."},
    "command": {"category": "behavior", "severity": "medium", "description": "Shell/PowerShell command text."},
    "persistence": {"category": "behavior", "severity": "medium", "description": "Autostart, service or scheduled-task persistence."},
    "credential": {"category": "behavior", "severity": "low", "description": "Credential-, password- or token-related text."},
    "credential_theft": {"category": "behavior", "severity": "high", "description": "Credential dumping or secret-store access."},
    "crypto": {"category": "behavior", "severity": "info", "description": "Cryptographic algorithm or encoding usage."},
    "anti_debug": {"category": "behavior", "severity": "low", "description": "Debugger detection or anti-analysis API."},
    "evasion": {"category": "behavior", "severity": "medium", "description": "Defense evasion, sandbox or AV/EDR interaction."},
    "injection": {"category": "behavior", "severity": "high", "description": "Process injection or remote-memory APIs."},
    "process": {"category": "behavior", "severity": "low", "description": "Process enumeration or manipulation."},
    "privilege": {"category": "behavior", "severity": "medium", "description": "Privilege escalation or elevated execution."},
    "lateral": {"category": "behavior", "severity": "medium", "description": "Lateral movement or remote execution."},
    "wmi": {"category": "behavior", "severity": "low", "description": "WMI usage or WMI class/path."},
    "exfiltration": {"category": "behavior", "severity": "medium", "description": "Upload, webhook or data-transfer service."},
    "ransomware": {"category": "behavior", "severity": "high", "description": "Ransom note or file-recovery language."},
    "uac_bypass": {"category": "behavior", "severity": "medium", "description": "Known UAC-bypass technique."},
    "sql": {"category": "behavior", "severity": "info", "description": "SQL statement text."},
    "encoded": {"category": "behavior", "severity": "low", "description": "Base64/PowerShell encoding marker."},
}

ENTITY_TYPES = (
    "url",
    "domain",
    "ip",
    "email",
    "path",
    "registry",
    "wallet",
    "hash",
    "filename",
    "user_agent",
    "jwt",
    "environment",
    "named_pipe",
)

RISK_LEVELS = ("info", "low", "medium", "high")
_RISK_WEIGHT = {name: index for index, name in enumerate(RISK_LEVELS)}
MAX_ENTITIES_PER_TYPE = 32

_TLDS = frozenset(
    """
    com net org ru xyz io dev app cn info biz top site online club shop us uk
    de fr eu in br jp kr au ca es it nl pl se no fi dk ch at be cz pt gr tr ua
    kz by ir il sa ae za mx ar cl co me tv cc ly to ws su pw onion ai tech store
    support live life world today space website fun icu buzz cloud network email
    link click download stream
    """.split()
)

_URL_RE = re.compile(r"(?i)(?<![A-Za-z0-9_])(?:https?|ftp)://[^\s\"'<>]{3,2048}")
_DEFANGED_URL_RE = re.compile(r"(?i)(?<![A-Za-z0-9_])hxxps?://[^\s\"'<>]{3,2048}")
_DOMAIN_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_@.-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,24}(?![A-Za-z0-9-])"
)
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?![\d.])")
_EMAIL_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@"
    r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}(?![A-Za-z0-9-])"
)
_REGISTRY_RE = re.compile(
    r"(?i)\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|"
    r"HKLM|HKCU|HKCR|HKU|HKCC)\\[^\r\n\t\"'<>|]{1,512}"
)
_WIN_PATH_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])"
    r"(?:[A-Za-z]:\\[^\r\n\t\"'<>|]{1,512}|\\\\[A-Za-z0-9._$-]+\\[^\r\n\t\"'<>|]{1,512})"
)
_UNIX_PATH_RE = re.compile(r"(?<![\w:/])(/(?:[\w.@%+~-]+/){1,16}[\w.@%+~-]*)")
_ENV_RE = re.compile(r"%[A-Za-z_][A-Za-z0-9_()]{0,64}%|\$\([A-Za-z_][A-Za-z0-9_]{0,64}\)")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_BTC_RE = re.compile(r"(?i)(?<![A-Za-z0-9])(?:bc1[ac-hj-np-z02-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})(?![A-Za-z0-9])")
_ETH_RE = re.compile(r"(?<![A-Za-z0-9])0x[a-fA-F0-9]{40}(?![A-Fa-f0-9])")
_XMR_RE = re.compile(r"(?<![A-Za-z0-9])[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}(?![A-Za-z0-9])")
_HASH_RE = re.compile(r"(?i)(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})(?![A-Fa-f0-9])")
_FILENAME_RE = re.compile(
    r"(?i)(?<![\w.-])([\w.-]{1,128}\."
    r"(?:exe|dll|sys|scr|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|lnk|"
    r"msi|jar|py|pl|sh|docm?|xlsm?|pptm?|pdf|rtf|zip|rar|7z|tar|gz|iso|img|"
    r"bin|dat|tmp|log|json|xml|ya?ml|config|ini|db|sqlite|locked|encrypted|"
    r"key|pem|p12|pfx))(?![A-Za-z0-9])"
)
_PIPE_RE = re.compile(r"(?i)\\\\\.\\pipe\\[^\r\n\t\"'<>|]{1,256}")

# Behavior terms are checked in order.  They intentionally use lower-case
# substrings because API names are often embedded in longer strings.
_BEHAVIOR_TERMS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("http", (
        "http://", "https://", "hxxp://", "hxxps://", "user-agent",
        "content-type", "authorization:", "bearer ", "accept:", "post /",
        "get /", "put /", "delete /",
    )),
    ("network", (
        "http://", "https://", "ftp://", "socket", "ws2_32", "wininet",
        "winhttp", "internetopen", "internetconnect", "urldownload",
        "curl ", "wget ", "request.", "urllib", "libcurl",
    )),
    ("dns", (
        "dnsquery", "gethostbyname", "getaddrinfo", "nslookup", "dnsapi",
        "resolve", "ns_record", "dns ",
    )),
    ("download", (
        "download", "urldownloadtofile", "urlcache", "bitsadmin",
        "certutil -urlcache", "invoke-webrequest", "start-bitstransfer",
        "wget ", "curl -o",
    )),
    ("execution", (
        "createprocess", "shellexecute", "winexec", "createprocessasuser",
        "rundll32", "regsvr32", "mshta", "wscript", "cscript",
    )),
    ("command", (
        "cmd.exe", "powershell", "pwsh", "/c ", "-enc ", "-encodedcommand",
        "invoke-expression", "iex(", "reg add", "sc create",
        "schtasks /create", "wmic ",
    )),
    ("persistence", (
        "currentversion\\run", "currentversion\\runonce", "\\runonce",
        "startup", "winlogon", "userinit", "shell\\open\\command",
        "schtasks /create", "sc create", "create service", "new-service",
        "startservice", "createservice", "taskscheduler",
    )),
    ("registry", (
        "hkey_", "hklm", "hkcu", "regopenkey", "regsetvalue", "regcreatekey",
        "regdeletekey", "regqueryvalue",
    )),
    ("credential", (
        "password", "passwd", "pwd=", "credential", "login", "logon",
        "api_key", "apikey", "secret", "token",
    )),
    ("credential_theft", (
        "lsass", "mimikatz", "sekurlsa", "ntds.dit", "sam\\", "dpapi",
        "minidump", "dumpcreds", "cryptunprotectdata",
    )),
    ("crypto", (
        "aes-", "aes_", "aes128", "aes192", "aes256", "rc4", "des-", "des_",
        "3des", "des ede", "encrypt", "decrypt", "cipher",
        "cryptacquirecontext", "bcrypt", "crypt32", "base64",
    )),
    ("anti_debug", (
        "isdebuggerpresent", "checkremotedebuggerpresent",
        "ntqueryinformationprocess", "beingdebugged", "outputdebugstring",
    )),
    ("evasion", (
        "virtualprotect", "amsi", "etw", "defender", "antivirus",
        "sandbox", "vmware", "virtualbox", "sandboxie", "unhook",
        "ntsetinformationthread",
    )),
    ("injection", (
        "virtualallocex", "writeprocessmemory", "createremotethread",
        "ntcreatethread", "queueuserapc", "setthreadcontext", "mapviewoffile",
        "ntmapviewofsection", "openprocess",
    )),
    ("process", (
        "createprocess", "shellexecute", "winexec", "terminateprocess",
        "toolhelp32", "enumprocesses", "openprocess",
    )),
    ("privilege", (
        "adjusttokenprivileges", "sedebugprivilege", "runas",
        "highestavailable", "requireadministrator", "uac",
    )),
    ("lateral", (
        "psexec", "winrm", "net use", "admin$", "ipc$", "smbexec",
        "wmiexec",
    )),
    ("wmi", (
        "wmic", "win32_process", "root\\cimv2", "managementobject",
        "win32_logicaldisk",
    )),
    ("exfiltration", (
        "webhook", "telegram", "discord", "pastebin", "dropbox", "mega.nz",
        "transfer.sh", "uploadfile", "sendfile", "ftp upload",
    )),
    ("ransomware", (
        "ransom", "your files", "recover your files", "decrypt key",
        "files are encrypted", "payment instructions",
    )),
    ("uac_bypass", (
        "fodhelper", "eventvwr", "computerdefaults", "sdclt", "cmstp",
        "uac bypass",
    )),
    ("sql", (
        "select ", "insert into", "update ", "delete from", "union select",
        "drop table", " from ", " where ",
    )),
    ("user_agent", (
        "mozilla/", "curl/", "wget/", "python-requests", "okhttp",
        "go-http-client",
    )),
    ("encoded", (
        "base64", "frombase64string", "to_base64", "b64decode",
        "-encodedcommand",
    )),
)

_USER_AGENT_PREFIXES = (
    "mozilla/", "curl/", "wget/", "python-requests/", "okhttp/",
    "go-http-client/", "libwww-perl/",
)

_TRAILING_PUNCTUATION = ".,;:!?)]}'\""


def string_id(ea: int, plaintext: str) -> str:
    """Stable, address-bound ID for a recovered string."""
    digest = hashlib.sha1(f"{int(ea):x}\0{plaintext}".encode("utf-8", "replace")).hexdigest()
    return f"s_{digest[:12]}"


def risk_weight(level: str) -> int:
    return _RISK_WEIGHT.get(str(level).lower(), 0)


def max_risk(tags: Iterable[str]) -> str:
    best = 0
    for tag in tags:
        definition = TAG_DEFINITIONS.get(str(tag).lower())
        if not definition:
            continue
        best = max(best, _RISK_WEIGHT.get(definition["severity"], 0))
    return RISK_LEVELS[best]


@dataclass(frozen=True)
class Intelligence:
    tags: tuple[str, ...]
    entities: dict[str, tuple[str, ...]]
    risk: str

    def entities_dict(self) -> dict[str, list[str]]:
        return {name: list(values) for name, values in self.entities.items() if values}


def _clean_value(value: str) -> str:
    return value.strip().strip(_TRAILING_PUNCTUATION)


def _domain_valid(value: str) -> bool:
    value = value.strip().rstrip(".").lower()
    if not value or len(value) > 253 or "." not in value:
        return False
    labels = value.split(".")
    if any(not label or len(label) > 63 for label in labels):
        return False
    if all(label.isdigit() for label in labels):
        return False
    return labels[-1] in _TLDS


def _ipv4_valid(value: str) -> bool:
    host, _, port = value.partition(":")
    octets = host.split(".")
    if len(octets) != 4:
        return False
    try:
        numbers = [int(part, 10) for part in octets]
    except ValueError:
        return False
    if any(number > 255 for number in numbers):
        return False
    if port:
        try:
            if not 1 <= int(port, 10) <= 65535:
                return False
        except ValueError:
            return False
    return True


def _url_host(value: str) -> str:
    match = re.match(r"(?i)^[a-z]+://([^/?#]+)", value)
    if not match:
        return ""
    authority = match.group(1).rsplit("@", 1)[-1]
    if authority.startswith("["):
        return ""
    return authority.split(":", 1)[0]


def _add_entity(entities: dict[str, list[str]], seen: dict[str, set[str]], name: str, value: str) -> None:
    value = _clean_value(value)
    if len(value) < 3 or len(value) > 2048:
        return
    bucket = entities.setdefault(name, [])
    if len(bucket) >= MAX_ENTITIES_PER_TYPE:
        return
    key = value.lower()
    if key in seen.setdefault(name, set()):
        return
    seen[name].add(key)
    bucket.append(value)


def _inside_spans(span: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
    start, end = span
    return any(left <= start and end <= right for left, right in spans)


def _extract_entities(text: str) -> dict[str, tuple[str, ...]]:
    entities: dict[str, list[str]] = {}
    seen: dict[str, set[str]] = {}
    url_spans: list[tuple[int, int]] = []

    for match in _URL_RE.finditer(text):
        url = _clean_value(match.group())
        if not url:
            continue
        url_spans.append((match.start(), match.end()))
        _add_entity(entities, seen, "url", url)
        host = _url_host(url)
        if host and _domain_valid(host):
            _add_entity(entities, seen, "domain", host)
        elif host and _ipv4_valid(host):
            _add_entity(entities, seen, "ip", host)

    for match in _DEFANGED_URL_RE.finditer(text):
        _add_entity(entities, seen, "url", _clean_value(match.group()))

    for match in _DOMAIN_RE.finditer(text):
        value = _clean_value(match.group())
        if not _domain_valid(value) or _inside_spans((match.start(), match.end()), url_spans):
            continue
        _add_entity(entities, seen, "domain", value)

    for match in _IPV4_RE.finditer(text):
        value = _clean_value(match.group())
        if _ipv4_valid(value):
            _add_entity(entities, seen, "ip", value)

    for match in _EMAIL_RE.finditer(text):
        value = _clean_value(match.group())
        if _domain_valid(value.rsplit("@", 1)[-1]):
            _add_entity(entities, seen, "email", value)

    for match in _PIPE_RE.finditer(text):
        _add_entity(entities, seen, "named_pipe", _clean_value(match.group()))

    for match in _REGISTRY_RE.finditer(text):
        _add_entity(entities, seen, "registry", _clean_value(match.group()))

    for match in _WIN_PATH_RE.finditer(text):
        value = _clean_value(match.group())
        if value.lower().startswith("\\\\.\\pipe\\"):
            continue
        _add_entity(entities, seen, "path", value)

    for match in _UNIX_PATH_RE.finditer(text):
        _add_entity(entities, seen, "path", _clean_value(match.group()))

    for match in _ENV_RE.finditer(text):
        _add_entity(entities, seen, "environment", _clean_value(match.group()))

    for match in _BTC_RE.finditer(text):
        _add_entity(entities, seen, "wallet", _clean_value(match.group()))
    for match in _ETH_RE.finditer(text):
        _add_entity(entities, seen, "wallet", _clean_value(match.group()))
    for match in _XMR_RE.finditer(text):
        _add_entity(entities, seen, "wallet", _clean_value(match.group()))

    for match in _HASH_RE.finditer(text):
        _add_entity(entities, seen, "hash", _clean_value(match.group()).lower())

    for match in _JWT_RE.finditer(text):
        _add_entity(entities, seen, "jwt", _clean_value(match.group()))

    for match in _FILENAME_RE.finditer(text):
        _add_entity(entities, seen, "filename", _clean_value(match.group()))

    lowered = text.strip().lower()
    if lowered.startswith(_USER_AGENT_PREFIXES):
        _add_entity(entities, seen, "user_agent", text.strip())

    return {
        name: tuple(sorted(values, key=str.lower))
        for name, values in entities.items()
        if values
    }


def analyze_text(text: str) -> Intelligence:
    """Extract entities and behavior tags from one recovered string."""
    if not text:
        return Intelligence((), {}, "info")
    entities = _extract_entities(text)
    lowered = text.lower()
    tags: list[str] = []

    # Content tags mirror the entity buckets and make facets cheap.
    if entities.get("url"):
        tags.extend(("url", "network", "http"))
    if entities.get("domain"):
        tags.extend(("domain", "dns"))
    if entities.get("ip"):
        tags.append("ip")
    if entities.get("email"):
        tags.append("email")
    if entities.get("path"):
        tags.append("path")
    if entities.get("registry"):
        tags.append("registry")
    if entities.get("wallet"):
        tags.append("wallet")
    if entities.get("hash"):
        tags.append("hash")
    if entities.get("filename"):
        tags.append("filename")
    if entities.get("user_agent"):
        tags.append("user_agent")
    if entities.get("jwt"):
        tags.append("jwt")
    if entities.get("environment"):
        tags.append("environment")
    if entities.get("named_pipe"):
        tags.append("named_pipe")

    for tag, terms in _BEHAVIOR_TERMS:
        if any(term in lowered for term in terms):
            tags.append(tag)

    # Preserve definition order and remove duplicates without losing behavior
    # priority.
    ordered: list[str] = []
    seen_tags: set[str] = set()
    for tag in tags:
        if tag in TAG_DEFINITIONS and tag not in seen_tags:
            seen_tags.add(tag)
            ordered.append(tag)
    return Intelligence(tuple(ordered), entities, max_risk(ordered))


def defang(value: str) -> str:
    """Defang an indicator for safe display in reports."""
    value = re.sub(r"(?i)^http", "hxxp", value)
    value = value.replace(".", "[.]")
    return value.replace("@", "[@]")


def defang_entity(entity_type: str, value: str) -> str:
    if entity_type in ("url", "domain", "ip", "email"):
        return defang(value)
    return value


def entity_type_counts(results: Iterable[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for result in results:
        for name in result.get("entities", {}) or {}:
            counts[name] = counts.get(name, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


# Import-name fragments that provide behavior context even when no string
# carries a useful tag.  Used by analyze_binary and get_string_context.
IMPORT_TERMS: dict[str, tuple[str, ...]] = {
    "network": (
        "internet", "winhttp", "ws2_", "wsa", "socket", "connect", "dns",
        "url", "http", "recv", "send",
    ),
    "injection": (
        "virtualallocex", "writeprocessmemory", "createremotethread",
        "ntcreatethread", "queueuserapc", "setthreadcontext", "mapviewoffile",
        "openprocess",
    ),
    "anti_debug": (
        "isdebuggerpresent", "checkremotedebuggerpresent",
        "ntqueryinformationprocess", "outputdebugstring",
    ),
    "evasion": (
        "virtualprotect", "amsi", "etw", "unhook", "ntsetinformationthread",
    ),
    "credential": (
        "lsass", "credential", "minidump", "dpapi", "cryptunprotectdata",
        "logonuser", "credenumerate",
    ),
    "execution": (
        "createprocess", "shellexecute", "winexec", "createprocessasuser",
        "system", "popen",
    ),
    "persistence": (
        "schtasks", "createservice", "startservice", "regsetvalue",
        "regcreatekey", "writeprivateprofilestring",
    ),
    "crypto": (
        "cryptacquirecontext", "cryptencrypt", "cryptdecrypt", "bcryptencrypt",
        "bcryptdecrypt", "cryptgenkey",
    ),
    "process": (
        "openprocess", "terminateprocess", "toolhelp32", "enumprocesses",
        "getcurrentprocess",
    ),
    "privilege": (
        "adjusttokenprivileges", "opentoken", "duplicatetoken",
        "lookupprivilegevalue",
    ),
    "lateral": ("wnetaddconnection", "netuseadd", "winrm", "psexec"),
}


def suspicious_imports(imports: Iterable[str], limit: int = 40) -> list[dict]:
    """Return imports that map to behavior categories."""
    output: list[dict] = []
    for imported in imports:
        lowered = str(imported).lower()
        categories = [
            category
            for category, terms in IMPORT_TERMS.items()
            if any(term in lowered for term in terms)
        ]
        if not categories:
            continue
        output.append({"import": str(imported), "categories": categories})
        if len(output) >= limit:
            break
    return output
