"""Alert ingestion: the normalised alert contract, the connector runner, and the pipeline.

`schema` is the contract between connectors (which produce `NormalizedAlert`s) and the
pipeline (which upserts, triages and stores them). `pipeline` is imported lazily by the
runner so that importing this package never pulls in the model client.
"""

from __future__ import annotations

from lighthouse.ingest.schema import EvidenceValue, NormalizedAlert

__all__ = ["EvidenceValue", "NormalizedAlert"]
