"""Output contract for "Ghost Data Still Exists" (Stage 0).

Everything in this module is a *constant transcribed from the repository*; no
logic that inspects evidence lives here. Each block names the file and section
it comes from so it can be verified independently. ``tests/test_output_contract.py``
re-parses the Markdown tables in ``problem_statement.md`` and ``AGENTS.md`` and
fails if this module drifts from them.

Contract facts that the repository does NOT settle (sort order of case_id and
resource_id, behaviour of COMPLETE with an empty array, ...) are deliberately
not encoded as constants here; see ``ghost_audit/README.md`` ("Ambiguities").
"""
from __future__ import annotations

import re
from enum import Enum
from typing import Dict, FrozenSet, NamedTuple, Pattern, Tuple

# --------------------------------------------------------------------------- #
# CSV layout
# Source: README.md "Output"; problem_statement.md "Required Output";
#         AGENTS.md section 6.3.
# --------------------------------------------------------------------------- #
CSV_COLUMNS: Tuple[str, ...] = ("case_id", "deletion_status", "steps_json")

# --------------------------------------------------------------------------- #
# Deletion statuses
# Source: problem_statement.md "Required Output" table; AGENTS.md section 6.3.
# --------------------------------------------------------------------------- #
STATUS_COMPLETE = "COMPLETE"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"
DELETION_STATUSES: Tuple[str, ...] = (
    STATUS_COMPLETE,
    STATUS_INCOMPLETE,
    STATUS_NOT_APPLICABLE,
)

# --------------------------------------------------------------------------- #
# Phases and their order
# Source: problem_statement.md "Rules" ("Order steps by phase: findings,
#         remediation, then verification").
# --------------------------------------------------------------------------- #
PHASE_FINDING = "FINDING"
PHASE_REMEDIATION = "REMEDIATION"
PHASE_VERIFICATION = "VERIFICATION"
PHASES: Tuple[str, ...] = (PHASE_FINDING, PHASE_REMEDIATION, PHASE_VERIFICATION)
PHASE_RANK: Dict[str, int] = {phase: rank for rank, phase in enumerate(PHASES)}

# --------------------------------------------------------------------------- #
# Step schema: exactly these seven keys (key order is not significant).
# Source: problem_statement.md "Required Output"; AGENTS.md section 6.3.
# --------------------------------------------------------------------------- #
STEP_KEYS: Tuple[str, ...] = (
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
)
STEP_STRING_KEYS: Tuple[str, ...] = tuple(k for k in STEP_KEYS if k != "step_no")


# --------------------------------------------------------------------------- #
# Allowed operations: (phase, operation, state), in TABLE ORDER.
# Source: problem_statement.md "Allowed Operations"; AGENTS.md section 6.4.
# The tuple order IS the operation ordering: problem_statement.md "Rules" says
# "Within each phase, follow the operation order in the table above".
# --------------------------------------------------------------------------- #
class OperationSpec(NamedTuple):
    phase: str
    operation: str
    state: str


OPERATION_SPECS: Tuple[OperationSpec, ...] = (
    # FINDING
    OperationSpec(PHASE_FINDING, "REPORT_REMAINING_RECORD", "PRESENT"),
    OperationSpec(PHASE_FINDING, "REPORT_EXPOSED_PII", "PRESENT"),
    OperationSpec(PHASE_FINDING, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
    OperationSpec(PHASE_FINDING, "REPORT_RESTORE_RISK", "ACTIVE"),
    # REMEDIATION
    OperationSpec(PHASE_REMEDIATION, "DISABLE_DATA_FLOW", "DISABLED"),
    OperationSpec(PHASE_REMEDIATION, "BLOCK_RESTORE", "BLOCKED"),
    OperationSpec(PHASE_REMEDIATION, "DELETE_RECORD", "ABSENT"),
    OperationSpec(PHASE_REMEDIATION, "REDACT_RECORD", "REDACTED"),
    OperationSpec(PHASE_REMEDIATION, "ANONYMIZE_RECORD", "ANONYMIZED"),
    # VERIFICATION
    OperationSpec(PHASE_VERIFICATION, "VERIFY_RECORD_ABSENT", "ABSENT"),
    OperationSpec(PHASE_VERIFICATION, "VERIFY_RECORD_PRESENT", "PRESENT"),
    OperationSpec(PHASE_VERIFICATION, "VERIFY_RECORD_REDACTED", "REDACTED"),
    OperationSpec(PHASE_VERIFICATION, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    OperationSpec(PHASE_VERIFICATION, "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
    OperationSpec(PHASE_VERIFICATION, "VERIFY_RESTORE_BLOCKED", "BLOCKED"),
)

OPERATION_SPEC_BY_NAME: Dict[str, OperationSpec] = {
    spec.operation: spec for spec in OPERATION_SPECS
}
# Global rank of an operation = its position in the table. Because the table is
# grouped by phase, comparing ranks inside one phase gives "table order".
OPERATION_RANK: Dict[str, int] = {
    spec.operation: rank for rank, spec in enumerate(OPERATION_SPECS)
}
ALLOWED_COMBINATIONS: FrozenSet[Tuple[str, str, str]] = frozenset(OPERATION_SPECS)
ALL_OPERATIONS: FrozenSet[str] = frozenset(OPERATION_SPEC_BY_NAME)
ALL_STATES: FrozenSet[str] = frozenset(spec.state for spec in OPERATION_SPECS)

# --------------------------------------------------------------------------- #
# Which phases a status may contain.
# Source: problem_statement.md "Required Output":
#   COMPLETE       -> "include only verification steps"
#   INCOMPLETE     -> "include findings, the complete remediation plan, and the
#                      checks that must pass afterward"
#   NOT_APPLICABLE -> "use an empty JSON array"
# --------------------------------------------------------------------------- #
STATUS_ALLOWED_PHASES: Dict[str, FrozenSet[str]] = {
    STATUS_COMPLETE: frozenset({PHASE_VERIFICATION}),
    STATUS_INCOMPLETE: frozenset(PHASES),
    STATUS_NOT_APPLICABLE: frozenset(),
}
# Phases that must each appear at least once for INCOMPLETE (same sentence).
INCOMPLETE_REQUIRED_PHASES: FrozenSet[str] = frozenset(PHASES)


# --------------------------------------------------------------------------- #
# evidence_id rules per (status, phase).
# Source: problem_statement.md "Rules" (last bullet); AGENTS.md sections 6.3 and
#         6.6; README.md "Before submitting, confirm that".
#   COMPLETE   + VERIFICATION : must cite a file_id / activity_id / audit_id
#   INCOMPLETE + FINDING      : must cite evidence
#   INCOMPLETE + REMEDIATION  : empty string
#   INCOMPLETE + VERIFICATION : empty string (future checks)
# --------------------------------------------------------------------------- #
class EvidenceRule(Enum):
    REQUIRED = "required"
    EMPTY = "empty"


EVIDENCE_RULES: Dict[Tuple[str, str], EvidenceRule] = {
    (STATUS_COMPLETE, PHASE_VERIFICATION): EvidenceRule.REQUIRED,
    (STATUS_INCOMPLETE, PHASE_FINDING): EvidenceRule.REQUIRED,
    (STATUS_INCOMPLETE, PHASE_REMEDIATION): EvidenceRule.EMPTY,
    (STATUS_INCOMPLETE, PHASE_VERIFICATION): EvidenceRule.EMPTY,
}

# Shape of a citable ID. NOT stated in the Markdown contract; derived from the
# three ID columns in the dataset (evidence_files.csv `file_id`,
# system_activity.csv `activity_id`, user_audit_log.csv `audit_id`), all of which
# match this pattern. The validator lets callers replace or disable it.
DEFAULT_EVIDENCE_ID_PATTERN: Pattern[str] = re.compile(r"(?:evidence|activity|audit)_\d+")

# --------------------------------------------------------------------------- #
# Relationships between phases (see README "Relationship checks" for which are
# enforced as errors and which as warnings).
# --------------------------------------------------------------------------- #
# EXPLICIT in the contract: AGENTS.md section 6.5, "Verification must cover the
# required final state for each remediated record or process." The table pairs
# every remediation with a verification of the *same state*:
#   DELETE_RECORD->ABSENT, REDACT_RECORD->REDACTED, ANONYMIZE_RECORD->ANONYMIZED,
#   DISABLE_DATA_FLOW->DISABLED, BLOCK_RESTORE->BLOCKED.
# so the rule is implemented as "same system_id, same resource_id, same state".

# IMPLIED by the "Meaning" column, and true for every INCOMPLETE row of
# sample_output.csv, but never stated as a rule: which remediation answers
# which finding. Used only for configurable pairing diagnostics.
FINDING_REMEDIATION_PAIRS: Dict[str, FrozenSet[str]] = {
    "REPORT_REMAINING_RECORD": frozenset({"DELETE_RECORD"}),
    "REPORT_EXPOSED_PII": frozenset({"REDACT_RECORD", "ANONYMIZE_RECORD"}),
    "REPORT_ACTIVE_DATA_FLOW": frozenset({"DISABLE_DATA_FLOW"}),
    "REPORT_RESTORE_RISK": frozenset({"BLOCK_RESTORE"}),
}
