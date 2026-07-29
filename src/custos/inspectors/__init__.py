"""Context inspectors . A12 inspects full agent context for IPI.

All inspectors implement :class:`custos.inspectors.base.ContextInspector`.
"""

from custos.inspectors.base import ContextInspector, ContextInspectorBase, InspectorRegistry
from custos.inspectors.ipi_defender import IPIDefender
from custos.schema import InjectionFinding, InputSource, InspectionResult, InspectionVerdict

__all__ = [
    "ContextInspector",
    "ContextInspectorBase",
    "InspectorRegistry",
    "IPIDefender",
    "InspectionResult",
    "InspectionVerdict",
    "InputSource",
    "InjectionFinding",
]
