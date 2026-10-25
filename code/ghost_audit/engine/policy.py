"""``deletion_rules.csv`` as data, plus the resource naming conventions the evidence follows.

The required ACTION for a category always comes from the rules file (DELETE / REDACT / ANONYMIZE / RETAIN); this module
only translates an action into the contract's operations. Prefix -> category/system tables are the verified naming
convention of the dataset (nine prefixes are confirmed by the public sample answers; the rest by the evidence's own
``system_id`` or the catalog target system and are marked unverified).
"""
from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Union

# action -> (finding operation when the record violates it, remediation operation, verification operation)
ACTION_OPS = {
    "DELETE": ("REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"),
    "REDACT": ("REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"),
    "ANONYMIZE": ("REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"),
}
DATA_FLOW_OPS = ("REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED")     # no rule row: a recreation path
RESTORE_OPS = ("REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED")                  # rule_14 retains the archive
RETAIN_VERIFY = "VERIFY_RECORD_PRESENT"

PREFIX_CATEGORY = {
    "account": "USER_PROFILE", "search": "SEARCH_INDEX_ENTRY", "support": "SUPPORT_MESSAGE", "analytics": "ANALYTICS_PROFILE",
    "export": "USER_EXPORT", "backup": "BACKUP_ARCHIVE", "data_flow": "DATA_FLOW", "audit_record": "SECURITY_AUDIT_LOG",
    "tombstone": "ACCOUNT_TOMBSTONE", "legal_hold": "LEGAL_HOLD_RECORD", "marketing": "MARKETING_PROFILE",
    "object": "SUPPORT_ATTACHMENT", "cache": "CACHE_ENTRY", "email_delivery": "EMAIL_DELIVERY_LOG",
}
# verified by the public sample answers: account, audit_record, analytics, search, support, export, backup, data_flow, tombstone
PREFIX_SYSTEM = {
    "account": "account_service", "search": "search_service", "support": "support_platform", "analytics": "analytics_platform",
    "export": "export_service", "backup": "backup_service", "data_flow": "integration_service", "audit_record": "security_service",
    "tombstone": "identity_service",
    # unverified by the samples: the evidence's own system_id / the catalog's target system
    "legal_hold": "legal_service", "marketing": "marketing_platform", "object": "object_storage",
    "cache": "cache_service", "email_delivery": "email_delivery_service",
}


def prefix_of(resource_id: str) -> str:
    return re.sub(r"_\d+$", "", resource_id)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    condition: str
    action: str


class Rules:
    def __init__(self, rules: Dict[str, Rule]) -> None:
        self.by_category = rules

    @classmethod
    def load(cls, dataset_dir: Union[str, Path]) -> "Rules":
        with open(Path(dataset_dir) / "deletion_rules.csv", encoding="utf-8", newline="") as h:
            return cls({r["data_category"]: Rule(r["rule_id"], r["data_category"], r["condition"], r["required_action"]) for r in csv.DictReader(h)})

    def action(self, category: str) -> Optional[str]:
        r = self.by_category.get(category)
        return r.action if r else None
