import asyncio
from importlib.metadata import version
from typing import Any

from filevet.core.pipeline import extract_text, scan
from filevet.core.report import Report
from filevet.policies import Policy

__version__ = version("filevet")
__all__ = ["Policy", "Report", "__version__", "ascan", "extract_text", "scan"]


async def ascan(*args: Any, **kwargs: Any) -> Report:
    return await asyncio.to_thread(scan, *args, **kwargs)
