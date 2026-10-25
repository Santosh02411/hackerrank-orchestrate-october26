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


# --------------------------------------------------------------------------- #
# Log events (Stage 1B)
# --------------------------------------------------------------------------- #
# Roles:
#   fact        an event that reports a resource and (usually) its state/identifiers -> Observation
#   start       "<x>_started": opens a lookup; its key fields become the trace context of the
#               fact event that follows in the same trace (never used on its own as a result)
#   ledger_row  `record_lookup`: same vocabulary as the flat JSON ledgers
#   diagnostic  infrastructure chatter inside platform services; counted, no Observation
#   meta        export_started / export_completed: completeness metadata -> SnapshotScope
@dataclass(frozen=True)
class LogEventSpec:
    event: str
    role: str
    record_type: Optional[str] = None
    state_field: Optional[str] = None   # the log's own state/flag field, kept verbatim (a string)


def _fact(event: str, record_type: str, state_field: Optional[str] = None) -> LogEventSpec:
    return LogEventSpec(event, "fact", record_type, state_field)


LOG_EVENT_SPECS: Dict[str, LogEventSpec] = {s.event: s for s in (
    _fact("profile_lookup_completed", "USER_PROFILE", "http_status"),
    _fact("index_query_completed", "SEARCH_INDEX_ENTRY", "result"),
    _fact("audit_record_read_completed", "SECURITY_AUDIT_LOG", "rows"),
    _fact("connector_config_read_completed", "DATA_FLOW", "enabled"),
    _fact("connector_config_loaded", "DATA_FLOW", "enabled"),
    _fact("connector_heartbeat", "DATA_FLOW", "enabled"),
    _fact("restore_policy_read_completed", "BACKUP_ARCHIVE", "restore_allowed"),
    _fact("restore_candidate_evaluated", "BACKUP_ARCHIVE", "eligible"),
    _fact("restore_authorization_completed", "BACKUP_ARCHIVE", "decision"),
    _fact("analytics_profile_read_completed", "ANALYTICS_PROFILE"),
    _fact("analytics_profile_read", "ANALYTICS_PROFILE", "direct_identifiers"),
    _fact("analytics_identity_scan", "ANALYTICS_PROFILE", "direct_identifiers"),
    _fact("contact_lookup_completed", "MARKETING_PROFILE", "email_opt_in"),
    _fact("support_ticket_read_completed", "SUPPORT_MESSAGE"),
    _fact("message_read", "SUPPORT_MESSAGE"),
    _fact("message_pii_scan", "SUPPORT_MESSAGE"),
    _fact("contact_query_completed", "SUPPORT_MESSAGE", "rows"),
    _fact("deletion_marker_check", "SUPPORT_MESSAGE", "marker_found"),
    _fact("attachment_pii_scan", "SUPPORT_ATTACHMENT"),
    _fact("thumbnail_failed", "SUPPORT_ATTACHMENT"),
    _fact("export_metadata_read_completed", "USER_EXPORT", "available"),
    _fact("export_download_check_completed", "USER_EXPORT", "available"),
    _fact("retained_order_loaded", "LEGAL_HOLD_RECORD", "access"),
    LogEventSpec("record_lookup", "ledger_row"),
    *(LogEventSpec(e, "start") for e in (
        "profile_lookup_started", "index_query_started", "audit_record_query_started", "audit_record_read_started",
        "connector_config_read_started", "analytics_profile_read_started", "analytics_profile_scan_started",
        "support_ticket_read_started", "message_scan_started", "restore_policy_read_started",
        "restore_policy_check_started", "export_download_check_started", "export_metadata_read_started",
        "attachment_scan_started", "retained_order_query_started", "contact_query_started")),
    *(LogEventSpec(e, "diagnostic") for e in (
        "connection_acquired", "cache_lookup", "dependency_retry", "dependency_recovered",
        "batch_started", "checkpoint_saved")),
    LogEventSpec("export_started", "meta"),
    LogEventSpec("export_completed", "meta"),
)}

# Services that only emit infrastructure chatter ("auxiliary events"). In the 11 logs that declare
# `expected_source_events`, that number equals the count of events from every OTHER service.
AUXILIARY_SERVICES = frozenset({
    "http_client", "runtime_config", "thread_pool", "webhook_delivery", "dns_cache", "lambda_extension",
    "secret_agent", "checkpoint_writer", "scheduler", "queue_consumer", "circuit_breaker", "feature_flags",
    "cert_agent", "kernel_monitor", "systemd", "log_router", "readback_collector",
})

# Key names that carry no identity/state and are left out of a start event's trace context
TRACE_CONTEXT_SKIP = frozenset({"logger", "instance", "pod", "region", "trace_id", "event", "attempt", "service"})
