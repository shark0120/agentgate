// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Reject codes of SPEC.md §7 and §9, shared by AgentGate and GateChecks.

// ── registry ──
error NotPrincipal();
error NotAuthorized();
error Terminal();
error InvalidCommit();
error InvalidParams();
error DelayTooShort();
error NothingPending();
error TooEarly();
error NotShrink();
error ConditionNotMet();
error CoSigInvalid();

// ── admission (SPEC §7.1) ──
error A1_MandateNotLive();
error A2_BadCapPath();
error A3_OutOfScope();
error A4_PreimageMismatch();
error A4_NotAttestor();
error A5_AttestationMismatch();
error A5_DuplicateAttestor();
error A5_SchemeNotAllowed();
error A5_RoleConflict();
error A5_BadAttestation();
error A5_BelowThreshold();
error A6_BadAgentSig();
error A7_NonceUsed();
error A8_OutsideValidity();
error A8_StaleState();
error A9_ExceedsBudget();
error A10_AssetMismatch();
error A11_PathMismatch();
error A12_BadLeafType();
error A13_ForbiddenTarget();
error A14_PreimageMismatch();
error A14_ArgRuleViolated();
error A15_AccountConfig();
error A16_ValueExceedsDeclared();
error A17_ImplementationUnsupported();

// ── delegation (SPEC §9) ──
error G1_CannotDelegate();
error G2_ExpiryWidens();
error G3_AllotmentMismatch();
error G4_BadChildBinding();

// ── execution (SPEC §7.2) ──
error X1_TicketMismatch();
error X2_WindowNotElapsed();
error X3_NoTicket();
error X4_StaleTicket();
error X5_CodeHashChanged();
error X6_AccountConfig();
error X6_SequencerDown();
error X7_OutflowExceeded();
error X7_InflowShort();
error X8_AllowanceIncreased();

// ── capability upkeep ──
error TicketStillLive();
error NodeStillLive();
error NoLiveAncestor();
