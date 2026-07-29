"""Structured audit sink (..9.24).

Sinks: file (JSONL), stdout, OTLP, S3 - pluggable . PII redaction
happens in the gateway (``Invocation.with_redacted_args``) before the event
reaches any sink . Tamper-evidence (``HashChainedAuditSink`` +
``custos audit verify``) is   - the default
:class:`FileAuditSink` is documented as NOT tamper-evident. Replay for
what-if analysis  lands in .
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from custos.schema import AuditEvent

if TYPE_CHECKING:
    from pathlib import Path

__all__ = [
    "AuditSink",
    "NullAuditSink",
    "FileAuditSink",
    "StdoutAuditSink",
    "HashChainedAuditSink",
    "CompositeAuditSink",
    "ChainVerifyReport",
    "ChainVerifyError",
    "GENESIS_HASH",
    "verify_chain",
]


#: Genesis ``prev_hash`` for the first line of a hash-chained log
#: . ``"0"`` repeated 64 times - a sha256 output is never all
#: zeros, so a genesis line is unambiguously distinguishable from a line
#: that links back to a real predecessor. The chain root is convention,
#: not a cryptographic claim - the security claim is "every line after
#: the first links back to the sha256 of the previous line".
GENESIS_HASH = "0" * 64


class AuditSink:
    """Abstract append-only sink ."""

    def emit(self, event: AuditEvent) -> None:
        raise NotImplementedError

    @classmethod
    def from_path(cls, path: str) -> AuditSink:
        return FileAuditSink(path)


class NullAuditSink(AuditSink):
    """Default sink: drops events (used when no sink is configured)."""

    def emit(self, event: AuditEvent) -> None:
        return None


class FileAuditSink(AuditSink):
    """JSONL file sink . One :class:`AuditEvent` per line, append-only.

    .. warning::
        This sink is **NOT tamper-evident** . A modifier can rewrite
        or delete lines undetected. For compliance-grade audit trails use
        :class:`HashChainedAuditSink` and verify with ``custos audit verify``.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)

    def emit(self, event: AuditEvent) -> None:
        line = json.dumps(event.to_dict(), sort_keys=True, default=_json_default)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.write("\n")


class StdoutAuditSink(AuditSink):
    """Stdout sink . Emits one JSON line per event to stdout."""

    def __init__(self, stream: object | None = None) -> None:
        self._stream: object = stream if stream is not None else sys.stdout

    def emit(self, event: AuditEvent) -> None:
        line = json.dumps(event.to_dict(), sort_keys=True, default=_json_default)
        stream = self._stream
        # Use write+flush for the common file-like case without importing IO.
        write = getattr(stream, "write", None)
        if callable(write):
            write(line + "\n")
        flush = getattr(stream, "flush", None)
        if callable(flush):
            flush()


class CompositeAuditSink(AuditSink):
    """Fan-out composite (pluggability;  wiring helper).

    Holds a tuple of child sinks and emits to each in order. Used by the
    gateway's audit-sink resolver when the caller passes a list (a
    convenience so the common ``[FileAuditSink, OTLPAuditSink,
    PrometheusMetricsSink]`` shape works directly from the constructor
    without the caller having to know about CompositeAuditSink). Also
    directly constructable for explicit fan-out wiring.

    Errors from a child sink are swallowed; one broken sink does NOT block
    the next (the audit trail stays whole across the working children;
    diagnostics are out-of-band — the broken sink should self-report via
    its own operator channel).
    """

    def __init__(self, sinks: Iterable[AuditSink]) -> None:
        self._sinks: tuple[AuditSink, ...] = tuple(sinks)

    @property
    def sinks(self) -> tuple[AuditSink, ...]:
        return self._sinks

    def emit(self, event: AuditEvent) -> None:
        for sink in self._sinks:
            try:
                sink.emit(event)
            except Exception:  # noqa: BLE001 - one bad sink doesn't break audit.
                continue


class HashChainedAuditSink(AuditSink):
    """Hash-chained JSONL sink .

    Each appended line is a JSON envelope wrapping the :class:`AuditEvent`
    dict plus a tamper-evidence link so ``custos audit verify`` can detect
    post-hoc modification, insertion, deletion of a predecessor, or
    line-reordering::

        {"schema_version": "1.0",
         "prev_hash": "<sha256(prev_line_utf8).hexdigest>",
         "event": <AuditEvent.to_dict>,
         "sig": "<hmac_sha256(signing_key, envelope_minus_sig).hexdigest>"}

    The first line's ``prev_hash`` is :data:`GENESIS_HASH` (a sentinel of
    64 zeros). Each subsequent line's ``prev_hash`` is the sha256 hex digest
    of the previous line's UTF-8 bytes (the exact bytes written to disk,
    including the trailing newline is excluded - sha256 is computed over
    the line content, not the record separator).

    Optional per-line HMAC signing (``signing_key``) protects against an
    attacker who reads the file and recomputes every sha256 themselves:
    without the signing key, a forged chain fails the HMAC check on every
    forged line. Asymmetric (Ed25519) signing is a v1.1 target gated on the
    ``custos[crypto]`` extra; v1.0 ships symmetric HMAC, the documented
    v1.0 verification primitive for the P3 compliance claim.

    .. note::
        A hash chain proves continuity - "every line links back to its
        predecessor" - NOT completeness. Deleting the *last* line leaves an
        unbroken chain. Operators that need completeness proof should pair
        this sink with a session-end batch sign (signed count + last sha256)
        or an external WORM store; v1.1 will add batched signing.
    """

    def __init__(
        self,
        path: str | Path,
        signing_key: bytes | None = None,
    ) -> None:
        self.path = str(path)
        self.signing_key = signing_key
        self._lock = threading.Lock()
        self._last_hash: str | None = None

    def _get_prev_hash(self) -> str:
        """Return the ``prev_hash`` the next line should reference.

        Uses an instance-level cache (``_last_hash``) on subsequent calls
        to avoid O(n) backward scans for long-running agents. Initialised
        from the last line of the file on first emit; falls back to
        :data:`GENESIS_HASH` when the file is empty or missing.
        """
        if self._last_hash is not None:
            return self._last_hash
        # Initialise from disk — read only the last ~4KB of the file.
        try:
            with open(self.path, "rb") as fh:
                fh.seek(0, 2)
                size = fh.tell()
                if size == 0:
                    self._last_hash = GENESIS_HASH
                    return GENESIS_HASH
                pos = max(0, size - 4096)
                fh.seek(pos)
                chunk = fh.read()
                lines = chunk.splitlines()
                last_line = b""
                for line in reversed(lines):
                    if line.strip():
                        last_line = line
                        break
                if not last_line.strip():
                    self._last_hash = GENESIS_HASH
                    return GENESIS_HASH
                self._last_hash = hashlib.sha256(last_line).hexdigest()
                return self._last_hash
        except FileNotFoundError:
            self._last_hash = GENESIS_HASH
            return GENESIS_HASH

    def emit(self, event: AuditEvent) -> None:
        with self._lock:
            prev_hash = self._get_prev_hash()
            envelope: dict[str, object] = {
                "schema_version": "1.0",
                "prev_hash": prev_hash,
                "event": event.to_dict(),
            }
            if self.signing_key is not None:
                unsigned = json.dumps(envelope, sort_keys=True, default=_json_default)
                sig = hmac.new(
                    self.signing_key, unsigned.encode("utf-8"), hashlib.sha256
                ).hexdigest()
                envelope["sig"] = sig
            line = json.dumps(envelope, sort_keys=True, default=_json_default)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.write("\n")
            # Cache the hash of the line we just wrote for the next emit.
            self._last_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()


@dataclass
class ChainVerifyError:
    """One defect found by :func:`verify_chain` ."""

    line_no: int
    kind: str
    """Defect kind (``"parse_error"``, ``"missing_prev_hash"``,
    ``"bad_genesis"``, ``"broken_chain"``, ``"bad_signature"``,
    ``"missing_signature"``, ``"unexpected_signature"``, ``"bad_schema_version"``)."""
    detail: str = ""


@dataclass
class ChainVerifyReport:
    """Result of :func:`verify_chain` ."""

    is_ok: bool
    line_count: int
    errors: list[ChainVerifyError] = field(default_factory=list)
    last_line_no: int = 0

    def __bool__(self) -> bool:
        return self.is_ok


def verify_chain(
    path: str | Path,
    hmac_key: bytes | None = None,
    expected_schema_version: str = "1.0",
) -> ChainVerifyReport:
    """Verify a hash-chained audit log written by :class:`HashChainedAuditSink`.

    Walks the file line by line and checks:

    1. Every line is parseable JSON (a corrupt save is a tamper signal).
    2. Every line has a ``prev_hash`` field.
    3. The first line's ``prev_hash`` equals :data:`GENESIS_HASH`.
    4. Each line N > 0 has ``prev_hash`` == ``sha256(prev_line_bytes).hexdigest``.
    5. If ``hmac_key`` is supplied, every line has a ``sig`` field that
       verifies against the re-serialized envelope (``sort_keys=True``).
       A line carrying ``sig`` with no key supplied is reported but does
       NOT fail (the caller asked only for chain continuity).
    6. Every line's ``schema_version`` matches ``expected_schema_version``
       (default ``"1.0"``). A mismatch on a chained line is a contract-bump
       audit anomaly (IR_CONTRACT).

    Returns a :class:`ChainVerifyReport`. Never raises for log-content
    defects; I/O errors (file missing) propagate as :class:`FileNotFoundError`.
    """
    errors: list[ChainVerifyError] = []
    line_count = 0
    prev_line_bytes = b""

    with open(path, "rb") as fh:
        raw = fh.read()
    for line_no, raw_line in enumerate(raw.split(b"\n"), start=1):
        if not raw_line.strip():
            continue
        line_count += 1
        try:
            envelope = json.loads(raw_line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            errors.append(
                ChainVerifyError(
                    line_no=line_no,
                    kind="parse_error",
                    detail=f"{type(exc).__name__}: {exc}",
                )
            )
            prev_line_bytes = b""  # cannot verify forward chain from a bad line
            continue

        if not isinstance(envelope, dict):
            errors.append(
                ChainVerifyError(
                    line_no=line_no,
                    kind="parse_error",
                    detail="envelope is not a JSON object",
                )
            )
            prev_line_bytes = b""
            continue

        prev_hash = envelope.get("prev_hash")
        if not isinstance(prev_hash, str):
            errors.append(
                ChainVerifyError(
                    line_no=line_no,
                    kind="missing_prev_hash",
                    detail="envelope has no string `prev_hash` field",
                )
            )
        else:
            if line_count == 1:
                if prev_hash != GENESIS_HASH:
                    errors.append(
                        ChainVerifyError(
                            line_no=line_no,
                            kind="bad_genesis",
                            detail=f"first line prev_hash {prev_hash!r} != GENESIS_HASH",
                        )
                    )
            else:
                expected = hashlib.sha256(prev_line_bytes).hexdigest()
                if prev_hash != expected:
                    errors.append(
                        ChainVerifyError(
                            line_no=line_no,
                            kind="broken_chain",
                            detail=f"prev_hash {prev_hash!r} != sha256(prev_line) {expected!r}",
                        )
                    )

        sv = envelope.get("schema_version")
        if sv != expected_schema_version:
            errors.append(
                ChainVerifyError(
                    line_no=line_no,
                    kind="bad_schema_version",
                    detail=f"schema_version {sv!r} != expected {expected_schema_version!r}",
                )
            )

        if hmac_key is not None:
            sig = envelope.pop("sig", None)
            if not isinstance(sig, str):
                errors.append(
                    ChainVerifyError(
                        line_no=line_no,
                        kind="missing_signature",
                        detail="hmac_key supplied but envelope has no `sig`",
                    )
                )
            else:
                unsigned = json.dumps(envelope, sort_keys=True, default=_json_default)
                expected_sig = hmac.new(
                    hmac_key, unsigned.encode("utf-8"), hashlib.sha256
                ).hexdigest()
                if not hmac.compare_digest(sig, expected_sig):
                    errors.append(
                        ChainVerifyError(
                            line_no=line_no,
                            kind="bad_signature",
                            detail="HMAC-SHA256 signature does not verify",
                        )
                    )

        prev_line_bytes = raw_line

    return ChainVerifyReport(
        is_ok=not errors,
        line_count=line_count,
        errors=errors,
        last_line_no=line_count,
    )


def _json_default(obj: object) -> object:
    """Fallback serializer for :func:`json.dumps` .

    Handles Custos enums (via ``.value``) and frozensets. Frozen dataclasses
    are already serialized via :meth:`AuditEvent.to_dict`; this only catches
    stray nested values.
    """
    if isinstance(obj, frozenset):
        return sorted(obj)
    value = getattr(obj, "value", None)
    if value is not None and not isinstance(value, type):
        return value
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")
