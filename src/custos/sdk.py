"""Python SDK: wrap plain callables with Custos gating (US-1).

``wrap_callables`` returns proxies with identical signatures that call
``Gateway.decide`` before invoking the underlying tool. On ``deny``/``defer``
the proxy raises :class:`PermissionDenied` and never invokes the tool.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any

from custos.exceptions import PermissionDenied
from custos.gateway import Gateway
from custos.schema import Decision, Invocation, SubjectContext, ToolDescriptor

__all__ = ["wrap_callables", "set_default_context", "get_default_context"]


# Module-level default subject context (used when a wrapped tool is called
# without an explicit ``custos_context`` kwarg). Tests can override it.
_default_context: SubjectContext = SubjectContext(user_id="default")


def set_default_context(ctx: SubjectContext) -> None:
    """Set the default :class:`SubjectContext` used by ``wrap_callables`` proxies."""
    global _default_context
    _default_context = ctx


def get_default_context() -> SubjectContext:
    """Return the current default :class:`SubjectContext`."""
    return _default_context


def wrap_callables(
    gateway: Gateway,
    tools: list[Callable[..., Any]] | tuple[Callable[..., Any], ...],
    *,
    descriptors: dict[str, ToolDescriptor] | None = None,
) -> list[Callable[..., Any]]:
    """Wrap a list of plain callables so every call is gated by the gateway (US-1).

    Each returned proxy has the same signature as the original (via
    :func:`functools.wraps`). At call time the proxy:

      1. Builds an :class:`Invocation` from the tool's name + bound args +
         a :class:`SubjectContext`.
      2. Calls ``gateway.decide(inv)``.
      3. On ``deny``/``defer`` raises :class:`PermissionDenied` and never
         invokes the tool.
      4. On ``allow`` / ``allow_once`` / ``allow_and_persist`` forwards to the
         underlying callable and returns its result.

    The tool name used in the :class:`Invocation` is the descriptor's ``name``
    when ``descriptors`` maps the callable's ``__name__`` to a descriptor
    (this lets policy tool globs like ``fs.read*`` match Python functions
    named ``fs_read``); otherwise the callable's ``__name__`` is used.

    The context is resolved from, in order: an explicit ``custos_context``
    kwarg passed at call time, else the module default (see
    :func:`set_default_context`).
    """
    descriptors = descriptors or {}
    wrapped: list[Callable[..., Any]] = []
    for tool in tools:
        py_name = getattr(tool, "__name__", None) or repr(tool)
        descriptor = descriptors.get(py_name) or _minimal_descriptor(py_name)
        # Use the descriptor's name (policy-space) when provided; else the
        # callable's __name__.
        tool_name = descriptor.name or py_name
        wrapped.append(_wrap_one(gateway, tool, tool_name, descriptor))
    return wrapped


def _minimal_descriptor(name: str) -> ToolDescriptor:
    """Build a minimal risk_tier=1 descriptor for tools without one."""
    return ToolDescriptor(name=name, risk_tier=1)


def _minimal_signature_args(
    tool: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Bind ``args``/``kwargs`` to ``tool``'s signature (US-1, shared with
    :class:`~custos.async_gateway.AsyncGateway`).

    Mirrors the binding logic in :func:`_wrap_one`'s sync ``proxy``: full
    :func:`inspect.signature.bind` with defaults applied; fallen back to a
    positional+kwargs union if the tool's signature is not introspectable.
    """
    sig = inspect.signature(tool)
    try:
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except TypeError:
        merged = dict(kwargs)
        merged.update(dict(zip(sig.parameters, args, strict=False)))
        return merged


def _wrap_one(
    gateway: Gateway,
    tool: Callable[..., Any],
    name: str,
    descriptor: ToolDescriptor,
) -> Callable[..., Any]:
    @functools.wraps(tool)
    def proxy(*args: Any, **kwargs: Any) -> Any:
        ctx = kwargs.pop("custos_context", None) or _default_context
        sig = inspect.signature(tool)
        try:
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            call_args = dict(bound.arguments)
        except TypeError:
            call_args = dict(kwargs)
            call_args.update(dict(zip(sig.parameters, args, strict=False)))
        inv = Invocation(
            tool=name,
            args=call_args,
            context=ctx,
            descriptor=descriptor,
        )
        decision = gateway.decide(inv)
        if decision in (Decision.DENY, Decision.DEFER):
            raise PermissionDenied(name, decision.value)
        return tool(*args, **kwargs)

    return proxy
