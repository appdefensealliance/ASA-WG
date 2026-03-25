"""Base utilities for GCP checks: session abstraction, helpers."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable

from ada_cloud_audit.checks.base import make_result
from ada_cloud_audit.models import Verdict

logger = logging.getLogger(__name__)


@dataclass
class GCPSession:
    """Lightweight GCP session holding credentials and project ID."""

    credentials: Any  # google.auth.credentials.Credentials
    project_id: str


def list_all_regions(session: GCPSession) -> list[str]:
    """Return list of available compute regions for the project."""
    from google.cloud import compute_v1

    client = compute_v1.RegionsClient(credentials=session.credentials)
    regions = []
    for region in client.list(project=session.project_id):
        if region.status == "UP":
            regions.append(region.name)
    return sorted(regions)


def list_all_zones(session: GCPSession) -> list[str]:
    """Return list of available compute zones for the project."""
    from google.cloud import compute_v1

    client = compute_v1.ZonesClient(credentials=session.credentials)
    zones = []
    for zone in client.list(project=session.project_id):
        if zone.status == "UP":
            zones.append(zone.name)
    return sorted(zones)


def list_all_instances(session: GCPSession) -> list[Any]:
    """Return all VM instances across all zones via aggregated list."""
    from google.cloud import compute_v1

    client = compute_v1.InstancesClient(credentials=session.credentials)
    instances = []
    agg = client.aggregated_list(project=session.project_id)
    for zone, response in agg:
        if response.instances:
            instances.extend(response.instances)
    return instances


def list_sql_instances(session: GCPSession) -> list[dict]:
    """List all Cloud SQL instances in the project.

    Uses the sqladmin API via googleapiclient.
    """
    from googleapiclient import discovery

    service = discovery.build(
        "sqladmin", "v1beta4", credentials=session.credentials
    )
    instances = []
    request = service.instances().list(project=session.project_id)
    while request is not None:
        response = request.execute()
        instances.extend(response.get("items", []))
        request = service.instances().list_next(
            previous_request=request, previous_response=response
        )
    return instances
