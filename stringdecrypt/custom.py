"""Custom decoder plugin hooks.

A custom decoder is a Python file with this minimal shape:

    NAME = "my_transform"
    DESCRIPTION = "optional text"

    def decode(data: bytes):
        result = ...           # bytes
        return result          # or a list of bytes, or None

Files are loaded from:
  * <package>/custom_decoders
  * any directory passed to ScanConfig.custom_dirs
  * <IDA plugin dir>/custom_decoders (when running inside IDA)

The hook is best-effort: import or runtime errors are recorded and never stop
the main scan.
"""

from __future__ import annotations

import importlib.util
import inspect
import os
import sys
from dataclasses import dataclass, field
from typing import Callable, Iterable


@dataclass
class CustomDecoder:
    name: str
    description: str
    path: str
    function: Callable


@dataclass
class CustomDecoderRegistry:
    decoders: list[CustomDecoder] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    loaded_dirs: list[str] = field(default_factory=list)

    def clear(self) -> None:
        self.decoders.clear()
        self.errors.clear()
        self.loaded_dirs.clear()

    def add(self, decoder: CustomDecoder) -> None:
        self.decoders = [item for item in self.decoders if item.name != decoder.name]
        self.decoders.append(decoder)

    def names(self) -> list[str]:
        return [decoder.name for decoder in self.decoders]

    def decode(self, data: bytes) -> list[tuple[str, bytes]]:
        results: list[tuple[str, bytes]] = []
        for decoder in self.decoders:
            try:
                if len(inspect.signature(decoder.function).parameters) >= 2:
                    value = decoder.function(data, None)
                else:
                    value = decoder.function(data)
            except Exception as error:  # noqa: BLE001 - custom code is untrusted
                self.errors.append(f"{decoder.name}: {type(error).__name__}: {error}")
                continue

            values: Iterable[bytes]
            if value is None:
                continue
            if isinstance(value, (bytes, bytearray)):
                values = [bytes(value)]
            elif isinstance(value, (list, tuple)):
                values = [bytes(item) for item in value if isinstance(item, (bytes, bytearray))]
            else:
                self.errors.append(f"{decoder.name}: decoder returned {type(value).__name__}, expected bytes/list/None")
                continue
            for item in values:
                if item and item not in (existing for _, existing in results):
                    results.append((decoder.name, item))
        return results


REGISTRY = CustomDecoderRegistry()


def _package_decoder_dir() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "custom_decoders")


def default_dirs(extra: Iterable[str] = ()) -> list[str]:
    candidates = [
        _package_decoder_dir(),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "custom_decoders"),
        *extra,
    ]
    result: list[str] = []
    seen: set[str] = set()
    for path in candidates:
        if not path:
            continue
        normalized = os.path.normcase(os.path.abspath(path))
        if normalized in seen:
            continue
        seen.add(normalized)
        result.append(path)
    return result


def load_decoders(directories: Iterable[str] | None = None, *, reload: bool = False) -> CustomDecoderRegistry:
    if reload:
        REGISTRY.clear()
    directories = default_dirs(directories or ())
    for directory in directories:
        if not os.path.isdir(directory):
            continue
        normalized = os.path.normcase(os.path.abspath(directory))
        if normalized in {os.path.normcase(os.path.abspath(path)) for path in REGISTRY.loaded_dirs}:
            continue
        REGISTRY.loaded_dirs.append(directory)
        for filename in sorted(os.listdir(directory)):
            if not filename.endswith(".py") or filename.startswith("_"):
                continue
            path = os.path.join(directory, filename)
            module_name = f"stringdecrypt_custom_{abs(hash(path)):x}_{filename[:-3]}"
            try:
                spec = importlib.util.spec_from_file_location(module_name, path)
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)
            except Exception as error:  # noqa: BLE001
                REGISTRY.errors.append(f"{path}: {type(error).__name__}: {error}")
                continue

            function = getattr(module, "decode", None)
            if not callable(function):
                continue
            name = str(getattr(module, "NAME", "") or os.path.splitext(filename)[0])
            description = str(getattr(module, "DESCRIPTION", "") or "")
            REGISTRY.add(CustomDecoder(name=name, description=description, path=path, function=function))
    return REGISTRY


def decoder_descriptions() -> list[dict]:
    return [
        {
            "name": decoder.name,
            "description": decoder.description,
            "path": decoder.path,
        }
        for decoder in REGISTRY.decoders
    ]
