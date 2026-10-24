"""Plaintext-quality scoring.

The goal is not to be a perfect language detector; it is to keep automatic
string decryption useful instead of flooding the analyst with random printable
garbage.
"""

from __future__ import annotations

import re
from functools import lru_cache

from .bytescan import shannon_entropy


COMMON_TOKENS = (
    "http://", "https://", "www.", ".com", ".net", ".org", ".ru", ".xyz",
    ".dll", ".exe", ".sys", ".tmp", ".json", ".txt", ".log", ".zip", ".rar",
    "\\windows\\", "\\system32\\", "\\appdata\\", "\\temp\\", "c:\\", "\\\\",
    "hkey_", "software\\", "currentversion", "microsoft\\", "system\\",
    "get", "set", "create", "open", "close", "read", "write", "load", "save",
    "error", "failed", "failure", "success", "warning", "invalid", "null",
    "true", "false", "user", "name", "path", "file", "data", "token", "key",
    "password", "passwd", "config", "debug", "test", "hello", "world",
    "content-type", "user-agent", "accept", "authorization", "bearer",
    "select ", "insert ", "update ", "delete ", " from ", " where ",
    "system.", "microsoft.", "windows.", "kernel32", "ntdll", "advapi32",
    "virtualalloc", "loadlibrary", "getprocaddress", "createthread",
    "api-ms-win-", "dll", "exe", "sys", "ms", "win", "api", "core",
    "process", "thread", "service", "driver", "software", "system32",
    "appdata", "programdata", "userprofile", "currentversion",
    "secret", "value", "virtual", "alloc", "address", "library", "function",
    "pointer", "memory", "buffer", "client", "server", "module", "plugin",
    "string", "crypto", "decrypt", "encrypt", "account", "profile",
)

URL_RE = re.compile(
    r"^(?:https?|ftp)://[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?::\d{1,5})?(?:/[^\s]*)?$",
    re.I,
)
DOMAIN_RE = re.compile(r"^(?:[a-z0-9-]+\.)+(?:com|net|org|ru|xyz|io|dev|app|cn|info|biz)$", re.I)
PATH_RE = re.compile(r"^(?:[a-z]:\\|\\\\|/)[^\0]{3,}$", re.I)
REG_RE = re.compile(r"^hkey_(?:local_machine|current_user|classes_root|users)\\", re.I)
JSON_RE = re.compile(r"^[\[{].*[\]}]$", re.S)
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)
IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{3,}$")
CAMEL_RE = re.compile(r"[a-z][A-Z]")
BASE64_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
HEX_ALPHABET = set("0123456789abcdefABCDEF")

_KNOWN_WORDS = {token.strip() for token in COMMON_TOKENS}

# A small general-English/technical vocabulary used only to derive letter
# bigrams.  The bigram table catches short random letter runs ("qde", "ypyty")
# without rejecting CamelCase identifiers assembled from known parts.
_COMMON_WORDS = """
the be to of and in that have it for not on with he as you do at this but
his by from they we say her she or an will my one all would there their what
so up out if about who get which go me when make can like time no just him
know take people into year your good some could them see other than then now
look only come its over think also back after use two how our work first well
way even new want because any these give day most us is are was were been
being has had did does done said made found called used where why while
before under between through during without within against around another
each every both few many much more less very same different large small long
short high low right left top bottom next last first second third
file path string text bytes data memory process thread module library
function pointer buffer error value name code word system windows kernel
driver service account profile config debug test key secret token password
user server client network socket connection request response header content
type accept agent authorization bearer http https example domain address
port command line argument option flag mode state event object class method
field list item index count size length start stop open close read write load
save create delete update insert select query table database message warning
invalid success failure failed unknown supported version release build
install check verify encrypt decrypt encode decode base cipher block stream
hash random number date month hour minute true false null none yes no enable
disable command execute process thread memory address library module handle
window message dialog button menu item sub get set proc addr hwnd str buf
ptr len num idx cnt arg cmd env reg sys mem obj cls url uri api dll exe cfg
ctx tmp src dst msg err
""".split()

_COMMON_BIGRAMS: set[str] = set()
for _word in _KNOWN_WORDS | set(_COMMON_WORDS):
    _letters = re.sub(r"[^a-z]", "", _word.lower())
    for _index in range(len(_letters) - 1):
        _COMMON_BIGRAMS.add(_letters[_index:_index + 2])

_TOKEN_PATTERNS = []
for _token in sorted(COMMON_TOKENS, key=len, reverse=True):
    _value = _token.strip()
    if not _value:
        continue
    _prefix = r"(?<![A-Za-z0-9_])" if _value[0].isalnum() else ""
    _suffix = r"(?![A-Za-z0-9_])" if _value[-1].isalnum() else ""
    _TOKEN_PATTERNS.append(_prefix + re.escape(_value) + _suffix)
_TOKEN_RE = re.compile("|".join(_TOKEN_PATTERNS), re.I)
_WORD_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")
_ALT_CASE_RE = re.compile(r"(?:[a-z][A-Z]){3,}")
_CONSONANT_RUN_RE = re.compile(r"[bcdfghjklmnpqrstvwxz]{5,}")
_BAD_SYMBOLS = set("|`~^{}[]")
_HEX_ONLY_RE = re.compile(r"^[0-9a-fA-F]+$")


def looks_like_base64_text(text: str) -> bool:
    if not text or any(ch.isspace() for ch in text):
        return False
    value = text.strip()
    if len(value) < 8 or len(value) > 8192:
        return False
    if not set(value) <= BASE64_ALPHABET:
        return False
    if value.count("=") > 2 or ("=" in value[:-2]):
        return False
    if len(value) % 4 not in (0, 2, 3):
        return False
    if any(ch.isdigit() or ch in "+/=" for ch in value):
        return True
    # All-letter Base64 is valid but rare; only accept text that does not look
    # like ordinary words (otherwise "ThisIsPlainEnglish" would match).
    letters = [ch for ch in value if ch.isalpha()]
    if letters:
        vowels = sum(1 for ch in letters if ch.lower() in "aeiouy")
        if 0.18 <= vowels / len(letters) <= 0.6:
            return False
    return True


def looks_like_base64_bytes(data: bytes) -> bool:
    try:
        return looks_like_base64_text(data.decode("ascii"))
    except UnicodeDecodeError:
        return False


def _text_printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for ch in text if ch.isprintable() or ch in "\t\r\n")
    return good / len(text)


def _vowel_ratio(text: str) -> float:
    letters = [ch.lower() for ch in text if ch.isalpha()]
    if not letters:
        return 0.0
    vowels = sum(1 for ch in letters if ch in "aeiouy")
    return vowels / len(letters)


def _case_chaos(text: str) -> float:
    letters = [ch for ch in text if ch.isalpha()]
    if len(letters) < 4:
        return 0.0
    changes = sum(1 for a, b in zip(letters, letters[1:]) if a.islower() != b.islower())
    # A normal CamelCase boundary produces two transitions (lower->upper and
    # upper->lower), so normalise by two.
    return changes / (2.0 * (len(letters) - 1))


def _bigram_plausibility(token: str) -> float:
    """Fraction of letter bigrams that occur in common words."""
    letters = re.sub(r"[^a-z]", "", token.lower())
    if len(letters) < 3:
        return 1.0
    bigrams = [letters[index:index + 2] for index in range(len(letters) - 1)]
    if not bigrams:
        return 1.0
    return sum(1 for bigram in bigrams if bigram in _COMMON_BIGRAMS) / len(bigrams)


def _wordlike(token: str) -> bool:
    """Cheap test for something that could be a natural/technical word."""
    alpha = token.rstrip("0123456789")
    if len(alpha) < 2 or not alpha.isalpha():
        return False
    known = alpha.lower() in _KNOWN_WORDS
    if alpha.isupper() and not known:
        # Acronym soup is a strong sign of XOR garbage.
        return False
    if _case_chaos(alpha) > 0.45:
        return False
    if _ALT_CASE_RE.search(alpha):
        # "oWoToWo" style alternation is a common XOR-garbage pattern, not a
        # normal CamelCase identifier.
        return False
    if _vowel_ratio(alpha) < 0.12:
        return False
    if _CONSONANT_RUN_RE.search(alpha.lower()) is not None:
        return False
    if len(alpha) >= 3 and not known and _bigram_plausibility(alpha) < 0.55:
        return False
    return True


def _sequential_ratio(text: str) -> float:
    if len(text) < 6:
        return 0.0
    steps = sum(1 for a, b in zip(text, text[1:]) if abs(ord(a) - ord(b)) == 1)
    return steps / (len(text) - 1)


def _identifier_parts(text: str) -> list[str]:
    """Split CamelCase, snake_case and digit boundaries into subwords."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", spaced)
    return [part for part in re.split(r"[^A-Za-z0-9]+", spaced) if part]


def _identifier_quality(text: str) -> tuple[bool, bool]:
    """Return (complete, has_known_word) for identifier-like text."""
    parts = _identifier_parts(text)
    if not parts:
        return False, False
    known = sum(1 for part in parts if part.lower() in _KNOWN_WORDS)
    good = sum(
        1
        for part in parts
        if part.lower() in _KNOWN_WORDS or _wordlike(part)
    )
    return good == len(parts), known > 0


def _uppercase_run_penalty(text: str) -> float:
    penalty = 0.0
    for match in re.finditer(r"[A-Z]{2,}", text):
        run = match.group()
        if run.lower() in _KNOWN_WORDS:
            continue
        if match.start() == 0 and len(run) == 2:
            continue
        penalty += 4.0
    return min(penalty, 12.0)


def _word_coherence(text: str) -> tuple[float, int]:
    words = [word for word in _WORD_SPLIT_RE.split(text) if len(word) >= 2]
    if not words:
        return 0.0, 0
    good = 0
    for word in words:
        if word.lower() in _KNOWN_WORDS or _wordlike(word):
            good += 1
    return good / len(words), len(words)


def _punctuation_penalty(text: str, *, url_like: bool, json_like: bool, path_like: bool) -> float:
    length = len(text)
    punctuation = sum(1 for ch in text if not ch.isalnum() and not ch.isspace())
    penalty = 0.0

    bad = 0
    for ch in text:
        if ch not in _BAD_SYMBOLS:
            continue
        if json_like and ch in "{}[]":
            continue
        bad += 1
    penalty += min(bad * 4.0, 20.0)

    if not url_like and not json_like:
        connectors = sum(1 for ch in text if ch in "&=")
        penalty += min(connectors * 2.5, 7.5)

    ratio = punctuation / length if length else 0.0
    if ratio > 0.28:
        penalty += min((ratio - 0.28) * 45.0, 15.0)

    if "://" in text and not url_like:
        penalty += 22.0

    if path_like and "\\" in text:
        penalty = max(0.0, penalty - 3.0)

    return penalty


def _score_text(text: str, *, original: bool = False) -> float:
    if not text:
        return 0.0

    length = len(text)
    printable_count = 0
    controls = letters = digits = spaces = non_ascii = punctuation = weird = 0
    for ch in text:
        code = ord(ch)
        if ch in "\t\r\n":
            printable_count += 1
            spaces += 1
            continue
        if 0x20 <= code <= 0x7E:
            printable_count += 1
            if ch.isalpha():
                letters += 1
            elif ch.isdigit():
                digits += 1
            elif ch == " ":
                spaces += 1
            else:
                punctuation += 1
            continue
        if ch.isprintable():
            printable_count += 1
        else:
            weird += 1
        if code < 32:
            controls += 1
        if code > 126:
            non_ascii += 1

    printable = printable_count / length
    if printable < 0.5:
        return printable * 25.0

    score = printable * 45.0
    score += min(length, 40) / 40.0 * 10.0
    score -= min(controls, 10) * 6.0

    if letters:
        letter_ratio = letters / length
        if 0.25 <= letter_ratio <= 1.0:
            score += 8.0
        if letters >= 4:
            vowel_ratio = _vowel_ratio(text)
            if 0.15 <= vowel_ratio <= 0.65:
                score += 5.0
            elif vowel_ratio < 0.08:
                score -= 8.0

    if digits:
        digit_ratio = digits / length
        if digit_ratio <= 0.45:
            score += 4.0
        elif digit_ratio > 0.75:
            score -= 10.0

    if spaces and len([w for w in re.split(r"\s+", text) if len(w) >= 2]) >= 2:
        score += 5.0

    token_hits = len({match.group(0).lower() for match in _TOKEN_RE.finditer(text)})
    score += min(token_hits, 4) * 4.0

    url_like = bool(URL_RE.match(text))
    domain_like = bool(DOMAIN_RE.match(text))
    path_like = bool(PATH_RE.match(text))
    reg_like = bool(REG_RE.match(text))
    json_like = bool(JSON_RE.match(text))
    ip_like = bool(IP_RE.match(text))
    email_like = bool(EMAIL_RE.match(text))

    if url_like:
        score += 18.0
    if domain_like:
        score += 10.0
    if path_like:
        score += 9.0
    if reg_like:
        score += 14.0
    if ip_like:
        score += 12.0
    if email_like:
        score += 12.0
    if json_like:
        score += 10.0

    lower = text.lower()
    if lower.startswith(("api-ms-win-", "ext-ms-win-")):
        score += 12.0
    elif (
        len(text) >= 6
        and re.fullmatch(r"[A-Za-z0-9_.-]+", text)
        and any(ch in text for ch in "._-")
        and letters / length >= 0.5
    ):
        score += 4.0

    coherence, word_count = _word_coherence(text)
    if word_count >= 2:
        if coherence >= 0.8:
            score += 10.0
        elif coherence >= 0.6:
            score += 6.0
        elif coherence <= 0.35:
            score -= 14.0
        elif coherence <= 0.5:
            score -= 8.0
    elif word_count == 1 and coherence >= 1.0:
        score += 3.0

    # Decrypted garbage often has a very small vocabulary (" eq eq eq eq") or
    # is mostly single-character tokens ("e 3 e # j n ...").
    tokens = [token for token in _WORD_SPLIT_RE.split(text) if token]
    if len(tokens) >= 3 and len(set(tokens)) / len(tokens) <= 0.5:
        score -= 12.0
    if len(tokens) >= 4:
        single = sum(1 for token in tokens if len(token) == 1)
        if single >= len(tokens) * 0.5:
            score -= 10.0

    if length >= 10:
        diversity = len(set(text)) / length
        if diversity < 0.4:
            score -= 8.0

    if IDENTIFIER_RE.match(text):
        vowel_ratio = _vowel_ratio(text)
        if 0.15 <= vowel_ratio <= 0.6:
            complete, has_known = _identifier_quality(text)
            clean_identifier = (
                digits == 0
                and _case_chaos(text) <= 0.45
                and complete
                and has_known
            )
            score += 9.0 if clean_identifier else 0.0
            if clean_identifier and CAMEL_RE.search(text):
                score += 4.0

    score -= _punctuation_penalty(text, url_like=url_like, json_like=json_like, path_like=path_like)

    if spaces == 0 and _case_chaos(text) > 0.45:
        score -= 6.0
    score -= _uppercase_run_penalty(text)

    sequential = _sequential_ratio(text)
    if sequential > 0.5:
        score -= min((sequential - 0.5) * 30.0, 15.0)

    linebreaks = text.count("\n") + text.count("\r")
    if length >= 8 and linebreaks / length > 0.08:
        score -= min((linebreaks / length - 0.08) * 60.0, 10.0)
    lone_cr = text.count("\r") - text.count("\r\n")
    if lone_cr > 0:
        score -= min(lone_cr * 3.0, 9.0)

    if len(text) >= 12 and looks_like_base64_text(text):
        score -= 14.0
    if len(text) >= 16 and _HEX_ONLY_RE.match(text):
        score -= 10.0

    if re.search(r"(.)\1{4,}", text):
        score -= 8.0

    weird = sum(1 for ch in text if not (0x20 <= ord(ch) <= 0x7E or ch in "\t\r\n"))
    if weird:
        score -= min(weird * 8.0, 24.0)

    # High entropy is normal for ciphertext and suspicious for plaintext.
    entropy = shannon_entropy(text.encode("utf-8", "ignore"))
    if entropy > 5.0:
        score -= (entropy - 5.0) * 7.0

    if non_ascii:
        ratio = non_ascii / length
        if ratio > 0.35:
            score -= 8.0

    if punctuation > length * 0.45:
        score -= 6.0

    if original:
        # Original strings are already known to IDA; do not reward them as a
        # successful decryption.
        score -= 5.0

    if length < 6:
        score = min(score, 55.0)
    elif length < 8:
        score = min(score, 65.0)

    return max(0.0, min(100.0, score))


@lru_cache(maxsize=8192)
def _score_text_cached(text: str, original: bool) -> float:
    return _score_text(text, original=original)


def score_text(text: str, *, original: bool = False) -> float:
    """Score plaintext, caching short strings that repeat across candidates."""
    if not text:
        return 0.0
    if len(text) <= 512:
        return _score_text_cached(text, original)
    return _score_text(text, original=original)


def _decode_variants(data: bytes) -> list[tuple[str, str]]:
    variants: list[tuple[str, str]] = []

    variants.append(("latin-1", data.decode("latin-1", "replace")))

    try:
        variants.append(("utf-8", data.decode("utf-8")))
    except UnicodeDecodeError:
        pass

    data_len = len(data)
    nul_count = data.count(0)
    if data_len >= 4 and data_len % 2 == 0 and nul_count >= max(1, data_len // 8):
        try:
            text = data.decode("utf-16-le")
            if _text_printable_ratio(text) >= 0.75:
                variants.append(("utf-16le", text))
        except UnicodeDecodeError:
            pass
        try:
            text = data.decode("utf-16-be")
            if _text_printable_ratio(text) >= 0.75:
                variants.append(("utf-16be", text))
        except UnicodeDecodeError:
            pass

    # Deduplicate identical decoded text while keeping the first encoding.
    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for encoding, text in variants:
        if text in seen:
            continue
        seen.add(text)
        unique.append((encoding, text))
    return unique


def _score_bytes_uncached(data: bytes, *, original: bool = False) -> tuple[float, str, str]:
    if not data:
        return 0.0, "", "raw"

    best_score = -1.0
    best_text = ""
    best_encoding = "raw"
    for encoding, text in _decode_variants(data):
        value = score_text(text, original=original)
        # Prefer a real Unicode decode over latin-1 when scores are close.
        if encoding in ("utf-8", "utf-16le", "utf-16be"):
            value += 1.5
        if value > best_score:
            best_score = value
            best_text = text
            best_encoding = encoding
    return max(0.0, min(100.0, best_score)), best_text, best_encoding


@lru_cache(maxsize=4096)
def _score_bytes_cached(data: bytes, original: bool) -> tuple[float, str, str]:
    return _score_bytes_uncached(data, original=original)


def score_bytes(data: bytes, *, original: bool = False) -> tuple[float, str, str]:
    """Return (score, best_text, encoding)."""
    if not data:
        return 0.0, "", "raw"
    if len(data) <= 512:
        return _score_bytes_cached(data, original)
    return _score_bytes_uncached(data, original=original)


def score_hex_bytes(data: bytes) -> float:
    """Score raw bytes as if they were a printable hex/base64 blob."""
    if not data:
        return 0.0
    return score_text(data.decode("ascii", "replace"))
