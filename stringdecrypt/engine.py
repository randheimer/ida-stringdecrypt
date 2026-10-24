"""Automatic decryption engine.

The engine is intentionally independent of IDA so it can be unit-tested and
used from the CLI.  It tries cheap transforms exhaustively and only attempts
keyed ciphers against plausible key material.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, Iterable

from . import custom, keys, schemes, scoring
from .bytescan import printable_ratio, shannon_entropy


def _looks_textual(data: bytes) -> bool:
    """Fast prefilter before the more expensive full scoring pass."""
    if len(data) < 8:
        return True
    if printable_ratio(data) >= 0.75:
        return True
    # UTF-16LE/BE plaintext has a printable half in every other byte.
    for offset in (0, 1):
        half = data[offset::2]
        if len(half) >= 4 and printable_ratio(half) >= 0.85:
            return True
    return False


# Evidence that a shift of already-printable data produced real text rather
# than a Caesar-style rotation of the original identifier.
_STRONG_MARKERS = (
    b"://",
    b"www.",
    b"\\",
    b"/",
    b".dll",
    b".exe",
    b".sys",
    b".json",
    b".xml",
    b"hkey_",
    b"api-ms-win-",
    b"content-type",
    b"<?xml",
    b"select ",
    b"insert ",
    b"mozilla/",
)


def _has_strong_signal(data: bytes) -> bool:
    lowered = data.lower()
    if any(marker in lowered for marker in _STRONG_MARKERS):
        return True
    if len(data) >= 24 and data.count(b" ") >= 4:
        return True
    return False


@dataclass
class Candidate:
    ea: int
    raw: bytes
    kind: str = "string"
    encoding: str = "raw"
    text: str = ""
    xrefs: list[int] = field(default_factory=list)
    segment: str = ""
    file_offset: int | None = None
    source: str = "ida"

    @property
    def address(self) -> int:
        return self.ea

    def preview(self, limit: int = 120) -> str:
        if self.text:
            text = self.text
        else:
            try:
                text = self.raw.decode("utf-8")
            except UnicodeDecodeError:
                text = self.raw.decode("latin-1", "replace")
        return text[:limit].replace("\r", "\\r").replace("\n", "\\n")

    def to_dict(self) -> dict:
        return {
            "address": f"0x{self.ea:x}",
            "ea": self.ea,
            "file_offset": self.file_offset,
            "kind": self.kind,
            "encoding": self.encoding,
            "segment": self.segment,
            "xrefs": [f"0x{x:x}" for x in self.xrefs],
            "original": self.preview(240),
        }


@dataclass
class ScanConfig:
    min_length: int = 4
    min_score: float = 55.0
    max_results_per_candidate: int = 8
    result_score_delta: float = 8.0
    skip_plain_threshold: float = 60.0
    max_total_results: int = 5000
    max_heavy_candidates: int = 300
    max_cipher_keys: int = 64
    max_cipher_ops: int = 30000
    max_input_length: int = 8192
    max_pipeline_depth: int = 2

    enable_base64: bool = True
    enable_xor: bool = True
    enable_xorstr: bool = True
    enable_add: bool = True
    enable_sub: bool = True
    enable_rol: bool = True
    enable_rc4: bool = True
    enable_aes: bool = True
    enable_des: bool = True
    enable_heavy: bool = True
    enable_custom: bool = True
    force_heavy: bool = False
    max_entropy_blobs: int = 2048
    custom_dirs: list[str] = field(default_factory=list)

    user_keys: list[bytes] = field(default_factory=list)
    user_ivs: list[bytes] = field(default_factory=list)
    cribs: list[bytes] = field(default_factory=list)
    key_material: list[bytes] = field(default_factory=list)
    key_text: str = ""
    iv_text: str = ""
    crib_text: str = ""

    def prepare(self) -> None:
        if self.key_text:
            self.user_keys = keys.merge_material(self.user_keys, keys.parse_key_text(self.key_text), limit=512)
        if self.iv_text:
            self.user_ivs = keys.merge_material(self.user_ivs, keys.parse_key_text(self.iv_text), limit=128)
        if self.crib_text:
            parsed = keys.parse_key_text(self.crib_text)
            self.cribs = keys.merge_material(self.cribs, parsed, limit=128)
        if not self.cribs:
            self.cribs = list(keys.DEFAULT_CRIBS)


@dataclass
class ScanResult:
    candidate: Candidate
    scheme: str
    plaintext: str
    score: float
    key: bytes = b""
    iv: bytes = b""
    pipeline: str = ""
    encoding: str = ""
    details: str = ""

    def key_display(self) -> str:
        if not self.key:
            return ""
        try:
            text = self.key.decode("ascii")
            if text.isprintable() and text:
                return f"{self.key.hex()} ({text})"
        except UnicodeDecodeError:
            pass
        return self.key.hex()

    def to_dict(self) -> dict:
        data = self.candidate.to_dict()
        data.update({
            "scheme": self.scheme,
            "key": self.key_display(),
            "key_hex": self.key.hex(),
            "iv_hex": self.iv.hex(),
            "pipeline": self.pipeline,
            "plaintext": self.plaintext,
            "score": round(self.score, 2),
            "text_encoding": self.encoding,
            "details": self.details,
        })
        return data


class StringDecryptEngine:
    def __init__(self, config: ScanConfig | None = None):
        self.config = config or ScanConfig()
        self.config.prepare()
        self._candidate_results: dict[tuple[str, bytes, str], ScanResult] = {}
        self._current_candidate: Candidate | None = None
        self._original_score = 0.0
        self._heavy_candidates = 0
        self._cipher_ops = 0
        self._keys_ready = False
        self._aes_keys: list[tuple[str, bytes]] = []
        self._des_keys: list[tuple[str, bytes]] = []
        self._rc4_keys: list[bytes] = []
        self._aes_ivs: list[tuple[str, bytes]] = []
        self._des_ivs: list[tuple[str, bytes]] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def scan_candidates(
        self,
        candidates: Iterable[Candidate],
        progress: Callable[[int, int], None] | None = None,
        cancel: Callable[[], bool] | None = None,
    ) -> list[ScanResult]:
        candidates = list(candidates)
        if not self.config.key_material:
            self.config.key_material = keys.merge_material(
                self.config.key_material,
                [candidate.raw for candidate in candidates if 1 <= len(candidate.raw) <= 64],
                [candidate.text.encode("latin-1", "ignore") for candidate in candidates if candidate.text],
                limit=4096,
            )
        self._prepare_keys()

        results: list[ScanResult] = []
        total = len(candidates)
        for index, candidate in enumerate(candidates):
            if cancel and cancel():
                break
            results.extend(self.scan_candidate(candidate))
            if progress:
                progress(index + 1, total)
            if len(results) >= self.config.max_total_results:
                break
        results.sort(key=lambda item: (-item.score, len(item.pipeline), item.scheme))
        return results[:self.config.max_total_results]

    def scan_candidate(self, candidate: Candidate) -> list[ScanResult]:
        if not candidate.raw or len(candidate.raw) < self.config.min_length:
            return []
        if len(candidate.raw) > self.config.max_input_length:
            return []

        self._current_candidate = candidate
        self._candidate_results = {}
        self._prepare_keys()
        if candidate.text:
            self._original_score = scoring.score_text(candidate.text)
        else:
            self._original_score = scoring.score_bytes(candidate.raw)[0]
        variants = self._input_variants(candidate)
        for label, data in variants:
            if not data:
                continue
            self._analyze_cheap(data, prefix=f"{label}+" if label != "raw" else "", depth=0)

            if self._can_try_heavy(candidate):
                self._analyze_heavy(data, prefix=f"{label}+" if label != "raw" else "")
                self._heavy_candidates += 1

        results = list(self._candidate_results.values())
        results.sort(key=lambda item: (-item.score, len(item.pipeline), item.scheme, len(item.key)))
        # Prefer the best result for an identical plaintext and drop implausible
        # alternatives that are far below the winner.
        deduped: list[ScanResult] = []
        seen_text: set[str] = set()
        best_score = results[0].score if results else 0.0
        floor = max(self.config.min_score, best_score - self.config.result_score_delta)
        for result in results:
            if result.score < floor:
                continue
            if result.plaintext in seen_text:
                continue
            seen_text.add(result.plaintext)
            deduped.append(result)
            if len(deduped) >= self.config.max_results_per_candidate:
                break
        return deduped

    # ------------------------------------------------------------------
    # Input handling
    # ------------------------------------------------------------------
    def _input_variants(self, candidate: Candidate) -> list[tuple[str, bytes]]:
        variants: list[tuple[str, bytes]] = [("raw", candidate.raw)]
        if candidate.text:
            text_bytes = candidate.text.encode("latin-1", "ignore")
            if text_bytes:
                variants.append(("text", text_bytes))
            try:
                utf8 = candidate.text.encode("utf-8")
                if utf8 != text_bytes:
                    variants.append(("utf8", utf8))
            except UnicodeEncodeError:
                pass
        if candidate.encoding.startswith("utf-16"):
            narrow = candidate.raw.replace(b"\x00", b"")
            if narrow:
                variants.append(("narrow", narrow))

        unique: list[tuple[str, bytes]] = []
        seen: set[bytes] = set()
        for label, data in variants:
            if data and data not in seen:
                seen.add(data)
                unique.append((label, data))
        return unique

    # ------------------------------------------------------------------
    # Cheap transforms
    # ------------------------------------------------------------------
    def _analyze_cheap(self, data: bytes, prefix: str, depth: int) -> None:
        if depth > self.config.max_pipeline_depth:
            return
        if len(data) < 2 or len(data) > self.config.max_input_length:
            return

        if self.config.enable_base64 and schemes.is_base64_candidate(data):
            for _, decoded in schemes.base64_variants(data):
                self._consider(decoded, "base64", b"", prefix + "b64", data)
                if depth < self.config.max_pipeline_depth:
                    self._analyze_cheap(decoded, prefix + "b64 -> ", depth + 1)

        # Custom decoders may transform text that superficially looks like
        # plaintext, so run them before the skip-plain fast path.
        if self.config.enable_custom and depth == 0:
            for decoder_name, decoded in custom.REGISTRY.decode(data):
                pipeline = prefix + f"custom:{decoder_name}"
                self._consider(decoded, f"custom:{decoder_name}", b"", pipeline, data)
                self._nested_base64(decoded, pipeline, depth)

        # A string that already looks like good plaintext does not need to be
        # brute-forced through hundreds of keyed transforms.
        if (
            depth == 0
            and not self.config.force_heavy
            and self._original_score >= self.config.skip_plain_threshold
        ):
            return

        # A printable source has already been read as text by the analyst; a
        # Caesar-style shift of it will often look plausible without being a
        # real decryption.  Only accept strong evidence in that case.
        strong_floor = (
            85.0
            if (depth == 0 and not self.config.force_heavy and printable_ratio(data) >= 0.95)
            else None
        )

        def add_result(out: bytes, scheme: str, key: bytes, pipeline: str) -> None:
            if strong_floor is not None and not _has_strong_signal(out):
                return
            self._consider(out, scheme, key, pipeline, data, min_score=strong_floor)

        if self.config.enable_xor:
            for key in range(256):
                out = schemes.xor_single(data, key)
                add_result(out, "xor", bytes([key]), prefix + f"xor(0x{key:02x})")
                self._nested_base64(
                    out,
                    prefix + f"xor(0x{key:02x})",
                    depth,
                    require_strong=strong_floor is not None,
                )

        if self.config.enable_xorstr:
            statistical = strong_floor is None
            for key in keys.repeating_xor_keys(
                data,
                self.config.key_material,
                self.config.cribs,
                statistical=statistical,
            ):
                if len(key) <= 1:
                    continue
                out = schemes.xor_repeating(data, key)
                add_result(out, "xorstr", key, prefix + f"xorstr({len(key)}b)")
                self._nested_base64(
                    out,
                    prefix + f"xorstr({len(key)}b)",
                    depth,
                    require_strong=strong_floor is not None,
                )

        if self.config.enable_add:
            for key in range(256):
                out = schemes.add_bytes(data, key)
                add_result(out, "add", bytes([key]), prefix + f"add(0x{key:02x})")

        if self.config.enable_sub:
            for key in range(256):
                out = schemes.sub_bytes(data, key)
                add_result(out, "sub", bytes([key]), prefix + f"sub(0x{key:02x})")

        if self.config.enable_rol:
            for shift in range(1, 8):
                out = schemes.rol_bytes(data, shift)
                add_result(out, "rol", bytes([shift]), prefix + f"rol({shift})")
                rev = schemes.ror_bytes(data, shift)
                add_result(rev, "ror", bytes([shift]), prefix + f"ror({shift})")

    def _nested_base64(
        self,
        data: bytes,
        prefix: str,
        depth: int,
        *,
        require_strong: bool = False,
    ) -> None:
        if depth >= self.config.max_pipeline_depth:
            return
        if not self.config.enable_base64 or not schemes.is_base64_candidate(data):
            return
        for _, decoded in schemes.base64_variants(data):
            if require_strong and not _has_strong_signal(decoded):
                continue
            self._consider(decoded, "base64", b"", prefix + " -> b64", data)
            self._analyze_cheap(decoded, prefix + " -> b64 -> ", depth + 1)

    # ------------------------------------------------------------------
    # Heavy transforms
    # ------------------------------------------------------------------
    def _can_try_heavy(self, candidate: Candidate) -> bool:
        if not self.config.enable_heavy or self._heavy_candidates >= self.config.max_heavy_candidates:
            return False
        if len(candidate.raw) < 8:
            return False
        if self.config.force_heavy:
            return True
        # Keyed ciphers are only worth trying on binary-looking data; a blob
        # that is already printable is plaintext, a path or Base64.
        if printable_ratio(candidate.raw) >= 0.95 and candidate.kind == "data-ref":
            return False
        if candidate.kind in ("data", "data-ref", "entropy", "raw"):
            return True
        entropy = shannon_entropy(candidate.raw)
        printable = printable_ratio(candidate.raw)
        return entropy >= 3.1 and printable < 0.9

    def _analyze_heavy(self, data: bytes, prefix: str) -> None:
        if len(data) > 4096:
            return
        if self.config.enable_rc4:
            for key in self._rc4_keys:
                if self._cipher_ops >= self.config.max_cipher_ops:
                    return
                self._cipher_ops += 1
                out = schemes.rc4_decrypt(data, key)
                for trim_label, plain in schemes.text_variants(out):
                    suffix = "" if trim_label == "raw" else f"/{trim_label}"
                    self._consider(plain, "rc4", key, prefix + f"rc4({len(key)}b){suffix}", data)
                    self._nested_base64(plain, prefix + f"rc4({len(key)}b){suffix}", 0)

        if self.config.enable_aes:
            for size_label, key in self._aes_keys:
                for mode in ("ECB", "CBC"):
                    if self._cipher_ops >= self.config.max_cipher_ops:
                        return
                    if mode == "ECB":
                        ivs = [("", b"")]
                    else:
                        ivs = self._aes_ivs
                    for iv_label, iv in ivs:
                        for variant_label, block in schemes.block_variants(data, 16):
                            if self._cipher_ops >= self.config.max_cipher_ops:
                                return
                            self._cipher_ops += 1
                            try:
                                out = schemes.aes_decrypt(block, key, mode, iv)
                            except Exception:
                                continue
                            for pad_label, plain in schemes.unpad_variants(out, 16):
                                pipe = f"{prefix}aes-{mode.lower()}{size_label}/{variant_label}/{pad_label}"
                                if mode == "CBC":
                                    pipe += f"/iv={iv_label}"
                                self._consider(plain, "aes", key, pipe, data, iv=iv)
                                self._nested_base64(plain, pipe, 0)

        if self.config.enable_des:
            for size_label, key in self._des_keys:
                for mode in ("ECB", "CBC"):
                    if self._cipher_ops >= self.config.max_cipher_ops:
                        return
                    if mode == "ECB":
                        ivs = [("", b"")]
                    else:
                        ivs = self._des_ivs
                    for iv_label, iv in ivs:
                        for variant_label, block in schemes.block_variants(data, 8):
                            if self._cipher_ops >= self.config.max_cipher_ops:
                                return
                            self._cipher_ops += 1
                            try:
                                out = schemes.des_decrypt(block, key, mode, iv)
                            except Exception:
                                continue
                            for pad_label, plain in schemes.unpad_variants(out, 8):
                                pipe = f"{prefix}des-{mode.lower()}{size_label}/{variant_label}/{pad_label}"
                                if mode == "CBC":
                                    pipe += f"/iv={iv_label}"
                                self._consider(plain, "des", key, pipe, data, iv=iv)
                                self._nested_base64(plain, pipe, 0)

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------
    def _consider(
        self,
        data: bytes,
        scheme: str,
        key: bytes,
        pipeline: str,
        source: bytes,
        iv: bytes = b"",
        min_score: float | None = None,
    ) -> None:
        if not data or len(data) < 2:
            return
        if not _looks_textual(data):
            return
        score, text, encoding = scoring.score_bytes(data)
        threshold = self.config.min_score if min_score is None else max(self.config.min_score, min_score)
        if score < threshold or not text:
            return
        if scheme != "base64" and text == source.decode("latin-1", "replace"):
            return
        if len(text) < 2:
            return

        result_key = (scheme, key, text)
        existing = self._candidate_results.get(result_key)
        if existing and existing.score >= score:
            return
        self._candidate_results[result_key] = ScanResult(
            candidate=self._current_candidate,
            scheme=scheme,
            plaintext=text,
            score=score,
            key=key,
            iv=iv,
            pipeline=pipeline,
            encoding=encoding,
            details=f"input={len(source)}b output={len(data)}b",
        )

        # Avoid unbounded growth while still keeping the best results.
        if len(self._candidate_results) > self.config.max_results_per_candidate * 4:
            keep = sorted(
                self._candidate_results.values(),
                key=lambda item: (-item.score, len(item.pipeline)),
            )[:self.config.max_results_per_candidate * 2]
            self._candidate_results = {(item.scheme, item.key, item.plaintext): item for item in keep}

    # ------------------------------------------------------------------
    # Key preparation
    # ------------------------------------------------------------------
    def _prepare_keys(self) -> None:
        if self._keys_ready:
            return
        self._keys_ready = True
        if self.config.enable_custom:
            custom.load_decoders(self.config.custom_dirs)
        material = keys.rank_material(self.config.key_material)
        self._aes_keys = keys.aes_keys(self.config.user_keys, material)[:self.config.max_cipher_keys]
        self._des_keys = keys.des_keys(self.config.user_keys, material)[:self.config.max_cipher_keys]
        self._rc4_keys = keys.rc4_keys(self.config.user_keys, material, limit=self.config.max_cipher_keys)
        # CBC with many guessed IVs explodes the number of DES/AES operations.
        # The zero IV and analyst-supplied IVs cover virtually all real cases;
        # AES gets two extra material-derived IVs because it is cheap enough.
        self._aes_ivs = keys.iv_candidates(
            self.config.user_ivs, material[:16], 16
        )[:4]
        self._des_ivs = keys.iv_candidates(self.config.user_ivs, (), 8)[:2]


def result_to_json(results: Iterable[ScanResult]) -> str:
    return json.dumps([result.to_dict() for result in results], indent=2, ensure_ascii=False)
