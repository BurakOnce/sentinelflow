# 3. Ground truth labels are kept outside the log lines

Date: 2026-09-30

## Status

Accepted

## Context

Detection quality is measured by comparing alerts against the attacks the simulator injected.
That comparison needs to know, for every log line, whether it belongs to an attack and which
one. Putting that information into the log lines would make the data unrealistic and would let
detection logic see the answer.

Log lines have no natural identifier. nginx, sshd and iptables formats do not carry a request
or event id, and adding one would again diverge from real formats.

## Decision

The simulator writes attack labels to a separate stream: `data/labels/ground_truth.jsonl` in
file mode and the `labels.ground_truth` topic in Kafka mode. Vector forwards the file to the
same topic, so downstream consumers always read labels from Kafka.

Each label record references its log line by `line_sha256`, the SHA-256 of the raw line as
written, without the trailing newline. The pipeline computes the same digest on the raw message
it receives, which gives an exact join without changing the line.

Each record also carries the attack id, scenario, MITRE technique, stage, source, event time,
source IP, user and the start and end of the attack window. Window and entity fields allow
alert-level evaluation, where an alert is matched to an attack by entity and time overlap
rather than by individual lines.

Randomness is derived from the seed per component, per user and day, and per attack instance.
Enabling a scenario therefore does not change the baseline traffic produced for the same seed
and window.

## Consequences

- Log lines stay byte-for-byte realistic.
- Line-level and alert-level precision and recall can both be computed.
- Two identical lines would share a digest. Timestamps with microsecond or request-level
  variation make this rare, and both lines would belong to the same attack in practice.
- Normalization must keep the raw line or its digest for the join to work.
