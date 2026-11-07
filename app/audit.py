import json
import logging
from datetime import datetime, timezone


logger = logging.getLogger("secure_employee_api.audit")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)


def log_success(actor: str, operation: str, employee_id: int) -> None:
    """Log only explicit audit metadata, never request or response contents."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": actor,
        "operation": operation,
        "employee_id": employee_id,
        "result": "success"
    }
    logger.info("%s", json.dumps(event))
