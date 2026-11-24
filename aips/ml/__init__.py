"""Small, explainable machine-learning models written with the standard library only.

* :class:`CommandRiskModel` - online logistic regression over hashed tokens of an AI agent's tool call. It learns
  from labelled examples and from human approve / deny decisions, and explains a score by its top tokens.
* :class:`IsolationForest` - unsupervised anomaly scoring for numeric vectors (node telemetry, agent behaviour).

Both are advisory: they add evidence to AIPS's rule-based decisions and never block on their own.
"""

from .isolation import IsolationForest
from .risk import CommandRiskModel, default_risk_model

__all__ = ["CommandRiskModel", "IsolationForest", "default_risk_model"]
