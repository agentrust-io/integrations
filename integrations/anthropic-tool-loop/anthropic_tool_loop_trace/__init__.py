"""Record an Anthropic Messages API tool loop as AgenTrust Telemetry events and a signed TRACE record.

`Run`, `digest`, `ToolCatalog` and `ToolInfo` are standard library only. The recorder lives in
`anthropic_tool_loop_trace.recorder` and needs agentrust-telemetry and agentrust-trace.
"""

from .catalog import ToolCatalog, ToolInfo
from .spool import Run, default_spool_path, digest

__version__ = "0.1.0"
__all__ = ["Run", "digest", "default_spool_path", "ToolCatalog", "ToolInfo", "__version__"]
