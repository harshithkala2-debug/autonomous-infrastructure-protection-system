"""Google Cloud integration (REST APIs, standard library only).

* ``auth``      - access tokens: metadata server, gcloud CLI, environment, service-account key
* ``client``    - authenticated JSON client with retries, pagination and operation polling
* ``discovery`` - builds an AIPS inventory from Compute Engine and IAM
* ``sources``   - telemetry: Cloud Monitoring, firewall config, exposure, Cloud Audit Logs, Security Command Center
* ``adapter``   - actions: VM reset, MIG resize / restart, firewall deny rules, quarantine, config restore,
                  service-account disable / enable - each with a rollback
"""

from .adapter import GcpAdapter
from .auth import TokenProvider, default_token_provider
from .client import GcpClient, GcpError
from .discovery import GcpDiscovery
from .sources import GcpTelemetrySource

__all__ = ["GcpAdapter", "GcpClient", "GcpDiscovery", "GcpError", "GcpTelemetrySource", "TokenProvider",
           "default_token_provider"]
