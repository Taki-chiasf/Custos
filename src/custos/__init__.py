"""Custos: drop-in permission middleware for AI agents.

 . Public surface grows as phases progress; only the core
abstractions are exported at this stage.
"""

from __future__ import annotations

from custos.assistants.base import Assistant, AssistantAsync
from custos.async_gateway import AsyncGateway
from custos.audit import FileAuditSink, StdoutAuditSink
from custos.fatigue import FatigueDecision, FatigueLayer, FatigueLayerAsync, InMemoryFatigueLayer
from custos.gateway import Gateway
from custos.policy import Policy
from custos.responders import MultiApproverResponder
from custos.responders.base import Responder, ResponderAsync
from custos.schema import (
    AssistantOutput,
    AuditEvent,
    Decision,
    Invocation,
    PolicyOutcome,
    PromptRequest,
    PromptResponse,
    SideEffect,
    SubjectContext,
    ToolDescriptor,
)

__version__ = "1.1.0a1"

__all__ = [
    "Gateway",
    "AsyncGateway",
    "Policy",
    "Decision",
    "PolicyOutcome",
    "SideEffect",
    "ToolDescriptor",
    "SubjectContext",
    "Invocation",
    "AssistantOutput",
    "PromptRequest",
    "PromptResponse",
    "AuditEvent",
    "FileAuditSink",
    "StdoutAuditSink",
    "Assistant",
    "AssistantAsync",
    "Responder",
    "ResponderAsync",
    "FatigueLayer",
    "FatigueLayerAsync",
    "FatigueDecision",
    "InMemoryFatigueLayer",
    "MultiApproverResponder",
    "__version__",
]
