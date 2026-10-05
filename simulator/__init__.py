"""
simulator/__init__.py
─────────────────────────────────────────────────────────────────────────────
Exposes the public simulator API so the package can be imported cleanly:

    from simulator import (
        EventGenerator,
        PowerShellMacroSimulator,
        WMIRemoteExecutionSimulator,
        CertutilAbuseSimulator,
        NormalTrafficSimulator,
    )
"""

from base import EventGenerator
from powershell import PowerShellMacroSimulator
from wmi import WMIRemoteExecutionSimulator
from certutil import CertutilAbuseSimulator
from normal import NormalTrafficSimulator

__all__ = [
    "EventGenerator",
    "PowerShellMacroSimulator",
    "WMIRemoteExecutionSimulator",
    "CertutilAbuseSimulator",
    "NormalTrafficSimulator",
]

