"""Base utilities for Azure checks: session abstraction, helpers."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AzureSession:
    """Lightweight Azure session holding credentials and subscription ID."""

    credential: Any  # azure.identity.DefaultAzureCredential or similar
    subscription_id: str
