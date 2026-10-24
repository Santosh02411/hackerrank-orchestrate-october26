"""Static, source-derived layout tables used by the parsers.

Everything here describes *layouts that exist in the repository's evidence*
(verified by inspecting every JSON and SQL file); none of it is a deletion
decision. ``record_type`` values reuse the data-category vocabulary that the
evidence itself uses (flat ledgers' ``record_type`` field, ``deletion_rules.csv``
``data_category``) and are labelled ``derived_from_layout`` whenever the source
does not state them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, Optional, Pattern, Tuple

# --------------------------------------------------------------------------- #
# JSON collections (also the `collection_name` values of the SQL record tables)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class CollectionSpec:
    collection: str
    system_id: Optional[str]     # None => each record names its own `system`
    record_type: Optional[str]   # None => each record states its own `record_type`
    state_field: Optional[str]   # the source's own state/flag field, if the layout has one
    ledger_like: bool = False


COLLECTION_SPECS: Dict[str, CollectionSpec] = {s.collection: s for s in (
    CollectionSpec("customer_profiles", "account_service", "USER_PROFILE", "account_status"),
    CollectionSpec("customer_search_documents", "search_service", "SEARCH_INDEX_ENTRY", None),
    CollectionSpec("customer_analytics_reports", "analytics_platform", "ANALYTICS_PROFILE", None),
    CollectionSpec("backup_catalog", "backup_service", "BACKUP_ARCHIVE", "restore_allowed"),
    CollectionSpec("customer_export_jobs", "export_service", "USER_EXPORT", "download_available"),
    CollectionSpec("deleted_customer_references", "identity_service", "ACCOUNT_TOMBSTONE", "account_status"),
    CollectionSpec("connector_configurations", "integration_service", "DATA_FLOW", "enabled"),
    CollectionSpec("retained_order_records", "legal_service", "LEGAL_HOLD_RECORD", None),
    CollectionSpec("security_audit_events", "security_service", "SECURITY_AUDIT_LOG", None),
    CollectionSpec("support_conversations", "support_platform", "SUPPORT_MESSAGE", None),
    CollectionSpec("ticket_attachments", "support_platform", "SUPPORT_ATTACHMENT", None),
    CollectionSpec("operational_record_history", None, None, "result", ledger_like=True),
)}

# --------------------------------------------------------------------------- #
# service_resource_export sections: (service, list key)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ServiceSectionSpec:
    service: str
    list_key: str
    kind: str                 # "record" | "lookup"
    record_type: str
    state_field: Optional[str]
    expand_hits: bool = False


SERVICE_SECTION_SPECS: Dict[Tuple[str, str], ServiceSectionSpec] = {(s.service, s.list_key): s for s in (
    ServiceSectionSpec("account_service", "profile_lookups", "lookup", "USER_PROFILE", "status_code"),
    ServiceSectionSpec("analytics_platform", "profiles", "record", "ANALYTICS_PROFILE", None),
    ServiceSectionSpec("backup_service", "restore_entries", "record", "BACKUP_ARCHIVE", "restore_allowed"),
    ServiceSectionSpec("export_service", "exports", "record", "USER_EXPORT", None),
    ServiceSectionSpec("integration_service", "connectors", "record", "DATA_FLOW", "enabled"),
    ServiceSectionSpec("search_service", "index_queries", "lookup", "SEARCH_INDEX_ENTRY", None, expand_hits=True),
    ServiceSectionSpec("security_service", "audit_records", "record", "SECURITY_AUDIT_LOG", None),
    ServiceSectionSpec("support_platform", "tickets", "record", "SUPPORT_MESSAGE", None),
)}

# single-collection files: top-level `collection` -> system
SINGLE_COLLECTION_SYSTEMS: Dict[str, str] = {
    "customer_export_jobs": "export_service",
    "customer_analytics_reports": "analytics_platform",
}

# --------------------------------------------------------------------------- #
# SQL table layouts
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SqlTableLayout:
    layout: str                   # layout id used in coverage reports
    name_pattern: Pattern[str]
    required_columns: FrozenSet[str]
    system_id: Optional[str]      # None => per-row `origin_system` column
    record_type: Optional[str]
    state_field: Optional[str]
    updated_field: Optional[str]  # column holding last-write time (NOT observation time)
    time_basis: str               # "scope" (per-system snapshot_scope row) | "header"


def _cols(*names: str) -> FrozenSet[str]:
    return frozenset(names)


SQL_TABLE_LAYOUTS: Tuple[SqlTableLayout, ...] = (
    # --- inventory snapshots: typed tables + `snapshot_scope`
    SqlTableLayout("inventory_table", re.compile(r"customer_profiles"), _cols("resource_id", "customer_reference", "email", "account_status"),
                   "account_service", "USER_PROFILE", "account_status", "updated_at", "scope"),
    SqlTableLayout("inventory_table", re.compile(r"customer_search_documents"), _cols("resource_id", "email", "index_name"),
                   "search_service", "SEARCH_INDEX_ENTRY", None, "updated_at", "scope"),
    SqlTableLayout("inventory_table", re.compile(r"customer_analytics_profiles"), _cols("resource_id", "email", "audience_cohort"),
                   "analytics_platform", "ANALYTICS_PROFILE", None, "updated_at", "scope"),
    SqlTableLayout("inventory_table", re.compile(r"support_records"), _cols("resource_id", "requester_email", "message_excerpt"),
                   "support_platform", "SUPPORT_MESSAGE", None, "updated_at", "scope"),
    SqlTableLayout("inventory_table", re.compile(r"customer_exports"), _cols("resource_id", "owner_email", "object_key"),
                   "export_service", "USER_EXPORT", None, "updated_at", "scope"),
    SqlTableLayout("inventory_table", re.compile(r"connector_subscriptions"), _cols("resource_id", "enabled", "connector_name"),
                   "integration_service", "DATA_FLOW", "enabled", "updated_at", "scope"),
    SqlTableLayout("inventory_table", re.compile(r"backup_restore_entries"), _cols("resource_id", "restore_allowed", "archive_key"),
                   "backup_service", "BACKUP_ARCHIVE", "restore_allowed", "updated_at", "scope"),
    SqlTableLayout("inventory_table", re.compile(r"security_audit_records"), _cols("resource_id", "subject_reference", "retention_until"),
                   "security_service", "SECURITY_AUDIT_LOG", None, "updated_at", "scope"),
    # --- account profile primary/replica tables
    SqlTableLayout("account_profile_table", re.compile(r"customer_profiles_.+"), _cols("resource_id", "user_id", "full_name", "email", "account_status"),
                   "account_service", "USER_PROFILE", "account_status", "updated_at", "header"),
    # --- search primary
    SqlTableLayout("search_document_table", re.compile(r"search_documents_.+"), _cols("resource_id", "display_name", "email", "indexed_at"),
                   "search_service", "SEARCH_INDEX_ENTRY", None, "indexed_at", "header"),
    # --- JSON-in-SQL record tables (primary + replicas); recognised by columns, not by name
    SqlTableLayout("json_record_table", re.compile(r".+"), _cols("resource_id", "origin_system", "collection_name", "record_json", "updated_at"),
                   None, None, None, "updated_at", "header"),
)

SNAPSHOT_SCOPE_TABLE = "snapshot_scope"
SNAPSHOT_SCOPE_COLUMNS = _cols("origin_system", "captured_at")

_STORE_RE = re.compile(r"(?:customer_data|customer_profiles|search_documents)_(?P<suffix>.+)")


def classify_store(table: str) -> Tuple[Optional[str], Optional[str]]:
    """``table`` name -> (store_role, replica_name).

    ``..._primary`` is the primary; a suffix containing ``replica`` is a replica
    whose name is that suffix (``read_replica``, ``replica_ap_south``, ...).
    Anything else (inventory tables) has no topology role.
    """
    m = _STORE_RE.fullmatch(table)
    if not m:
        return None, None
    suffix = m.group("suffix")
    if suffix == "primary":
        return "primary", None
    if "replica" in suffix:
        return "replica", suffix
    return None, None


def match_sql_layout(table: str, columns: FrozenSet[str]) -> Optional[SqlTableLayout]:
    for layout in SQL_TABLE_LAYOUTS:
        if layout.name_pattern.fullmatch(table) and layout.required_columns <= columns:
            return layout
    return None


# file-level SQL layout label from the table layouts present
def sql_file_layout(table_layouts: FrozenSet[str]) -> str:
    if "snapshot_scope" in table_layouts or "inventory_table" in table_layouts:
        return "sql:inventory_snapshot"
    if "json_record_table" in table_layouts:
        return "sql:json_record_replicas"
    if "account_profile_table" in table_layouts:
        return "sql:account_profile_replicas"
    if "search_document_table" in table_layouts:
        return "sql:search_primary"
    return "sql:unknown"
