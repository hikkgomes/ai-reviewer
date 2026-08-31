"""Deterministic argument-size chunking for external analysers."""
from __future__ import annotations

import os
from collections.abc import Iterable, Iterator


class CommandChunkError(ValueError):
    """A single command argument cannot fit within the configured limit."""


def iter_command_chunks(
    values: Iterable[str],
    max_files: int,
    max_argument_bytes: int,
) -> Iterator[list[str]]:
    """Yield chunks bounded by file count and encoded argument bytes."""
    if max_files <= 0 or max_argument_bytes <= 0:
        raise ValueError("command chunk limits must be greater than zero")
    current: list[str] = []
    current_bytes = 0
    for value in values:
        encoded = len(os.fsencode(value)) + 1
        if encoded > max_argument_bytes:
            if current:
                yield current
                current = []
                current_bytes = 0
            raise CommandChunkError("one analyser path exceeds the command argument-byte limit")
        if current and (len(current) >= max_files or current_bytes + encoded > max_argument_bytes):
            yield current
            current = []
            current_bytes = 0
        current.append(value)
        current_bytes += encoded
    if current:
        yield current
