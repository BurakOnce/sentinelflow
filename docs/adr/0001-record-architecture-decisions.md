# 1. Record architecture decisions

Date: 2026-09-30

## Status

Accepted

## Context

SentinelFlow combines several moving parts: a log simulator, a message broker, a streaming
engine, a detection rule engine, an analytical store, a data lake and a batch orchestrator.
Choices made early (schemas, rule semantics, storage layout) constrain later work, and the
reasoning behind them is easy to lose once the code has moved on.

## Decision

Architecturally significant decisions are recorded as Architecture Decision Records, following
the format described by Michael Nygard. Each record lives in `docs/adr/` as
`NNNN-short-title.md` and contains the sections Status, Context, Decision and Consequences.

A record is immutable once accepted. A changed decision is captured in a new record that
supersedes the old one, and the old record's status is updated to point to it.

## Consequences

- The history of design choices is versioned together with the code.
- New contributors can read the reasoning without reconstructing it from commits.
- Writing a record adds a small amount of overhead to each significant change.
