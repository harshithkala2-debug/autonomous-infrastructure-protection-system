"""The AIPS web: every protected machine joined in one closed trust domain, run by one orchestrator (the hub).

* :mod:`.trust`   - the closed trust domain (issued credentials, signed requests and responses, revocation)
* :mod:`.human`   - human-only approvals an AI agent cannot fake
* :mod:`.storage` - protected, write-once, self-healing storage
* :mod:`.hub`     - the orchestrator
* :mod:`.node`    - a machine in the web (sandbox, storage or client roles)
"""

from .human import ApprovalError, HumanLock
from .hub import WebHub, make_server, serve_background
from .node import WebClient, WebNode
from .storage import ProtectedStore
from .trust import Credential, TrustDomain, TrustError

__all__ = ["ApprovalError", "Credential", "HumanLock", "ProtectedStore", "TrustDomain", "TrustError", "WebClient",
           "WebHub", "WebNode", "make_server", "serve_background"]
