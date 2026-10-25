# Porygon Profile-Scope Experiment v1

Status: **review pending**

Protocol: `porygon.research.protocol.v1`

Context schema: `porygon.runtime-context.v1`

## Experimental question

The experiment compares profile selection, not four different sensors. Every
arm receives the same run assignments and the same normalized Docker/process
evidence. No winner is selected before confirmatory results.

The four primary arms are:

1. **Global (`ARM-GLOBAL`)**: one profile fitted across all selected workloads,
   versions, replicas, and supported contexts in the fit split.
2. **Mutable tag (`ARM-TAG`)**: select a profile by the exact tag recorded at
   run start. The run manifest also records the resolved repository digest.
   If a tag resolves differently later, that drift is evidence rather than
   being silently rewritten.
3. **Digest-only (`ARM-DIGEST`)**: select by exact
   `repository@sha256:<64 hex>` artifact identity. This is the current v1
   production profile identity.
4. **Digest-plus-context (`ARM-CONTEXT`)**: select by exact repository digest
   plus the SHA-256 of the canonical security-relevant runtime-context document
   defined below.

There is no primary-analysis fallback between arms. A stratum with inadequate
independent fit runs returns `insufficient_profile`. A separately labelled
`ABL-FALLBACK` ablation may measure a fixed context → digest → global fallback
chain, but its results cannot be merged into the primary arm.

## Immutable workload coordinates

The following OCI index digests were resolved on 2026-08-20. Plan 005 must
resolve and record the exact platform manifest and local image ID before any
pilot, refuse a different index digest for these coordinates, and retain a
machine-readable image lock.

| Workload/version ID | Human tag | Frozen OCI index coordinate |
|---|---|---|
| `WL-NGX-V1` | `nginx:1.26.3-alpine` | `nginx@sha256:1eadbb07820339e8bbfed18c771691970baee292ec4ab2558f1453d26153e22d` |
| `WL-NGX-V2` | `nginx:1.28.0-alpine` | `nginx@sha256:30f1c0d78e0ad60901648be663a710bdadf19e4c10ac6782c235200619158284` |
| `WL-RDS-V1` | `redis:7.2.7-alpine` | `redis@sha256:ddd16a9b1575a774c7e62956be8daa1de5b32cfb5c25b7a216aefed8e0919f9b` |
| `WL-RDS-V2` | `redis:7.4.2-alpine` | `redis@sha256:02419de7eddf55aa5bcf49efb74e88fa8d931b4d77c07eff8a6b2144472b6952` |
| `WL-PG-V1` | `postgres:16.6-alpine` | `postgres@sha256:1d04b9ba1d4996401f2552b51beda8187f175c0645c091e4781134fc9c9a3eef` |
| `WL-PG-V2` | `postgres:17.2-alpine` | `postgres@sha256:7e5df973a74872482e320dcbdeb055e178d6f42de0558b083892c50cda833c96` |

A disappeared upstream artifact is a recorded environment failure. Replacing
it requires a new protocol version; a convenient new digest is not equivalent.

The mutable-tag arm does not depend on accidental upstream movement. Plan 005
creates controlled local aliases `porygon-study/nginx:mutable`,
`porygon-study/redis:mutable`, and `porygon-study/postgres:mutable`. Fit runs
resolve the alias to each family's V1 coordinate; predeclared drift runs move
the same alias to V2 while recording both the literal alias and resolved
digest. Other runs record their frozen human tag. This exposes tag-selection
failure deterministically without changing the underlying immutable artifacts.

## Runtime-context input

The fingerprint contains normalized configuration known before workload
execution:

- entrypoint shape and command shape;
- configured user class (`root`, `nonroot`, or `missing`);
- privileged and read-only-root-filesystem tri-state values;
- normalized network mode;
- sorted added and dropped Linux capabilities;
- sorted container device destinations and permission shape, never host paths;
- sorted published-port shape: container port/protocol, binding scope
  (`loopback`, `wildcard`, `specific`, or `missing`), and host-port mode
  (`fixed`, `ephemeral`, `none`, or `missing`);
- sorted mount destination, mount type, and read-only tri-state.

Entrypoint/command shape keeps only the executable basename, safe flag names,
and argument classes such as `<path>`, `<integer>`, `<url>`, `<flag-value>`,
`<secret-value>`, or `<positional>`. It never includes a literal argument value.
Secret-like flags (password, token, key, secret, credential) are represented as
`flag:<secret>` followed by `<secret-value>`.

The fingerprint excludes all environment values and names, literal argument
values, secret-bearing arguments, host-specific mount source paths, exact host
IP addresses, container IDs/names, image tags, timestamps, labels, health,
restart counts, PIDs, event counts, and mutable runtime counters.

## Missing values and canonicalization

- A missing scalar or tri-state field is the JSON string `"missing"`.
- A known empty collection is `[]`; a collection that the source could not
  inspect is `"missing"`.
- JSON object keys are sorted lexicographically.
- Capability lists and device, port, and mount records are normalized, then
  sorted by their canonical JSON representation.
- Entrypoint and command shape arrays retain order because argument position is
  part of command shape.
- Strings use Unicode NFC, lower-case enumerations, and no insignificant
  whitespace. Integers remain JSON integers; booleans remain booleans.
- The identity is SHA-256 of UTF-8 canonical JSON with separators `,` and `:`.
- The hashed document includes `schema_version`; a schema change cannot share
  an identity with v1.

Plan 005 must persist the canonical document, its hash, source snapshot hash,
normalization warnings, and implementation revision. Hash-only storage is
insufficient for audit.

## Canonical examples

The first two documents are semantically equal despite object and set-like
array order. The validator must produce one hash. The third changes privileged
mode and must produce a different hash.

```json context-example-equivalent-a
{
  "schema_version": "porygon.runtime-context.v1",
  "entrypoint_shape": ["exe:docker-entrypoint.sh"],
  "command_shape": ["exe:nginx", "flag:-g", "<flag-value>"],
  "configured_user": "nonroot",
  "privileged": false,
  "read_only_rootfs": true,
  "network_mode": "bridge",
  "capabilities": {"add": ["NET_BIND_SERVICE", "CHOWN"], "drop": ["SYS_ADMIN"]},
  "devices": [],
  "ports": [
    {"container_port": 8080, "protocol": "tcp", "binding_scope": "loopback", "host_port_mode": "ephemeral"}
  ],
  "mounts": [
    {"destination": "/cache", "type": "volume", "read_only": false},
    {"destination": "/etc/nginx/conf.d", "type": "bind", "read_only": true}
  ]
}
```

```json context-example-equivalent-b
{
  "mounts": [
    {"read_only": true, "type": "bind", "destination": "/etc/nginx/conf.d"},
    {"type": "volume", "destination": "/cache", "read_only": false}
  ],
  "ports": [
    {"host_port_mode": "ephemeral", "binding_scope": "loopback", "protocol": "tcp", "container_port": 8080}
  ],
  "devices": [],
  "capabilities": {"drop": ["SYS_ADMIN"], "add": ["CHOWN", "NET_BIND_SERVICE"]},
  "network_mode": "bridge",
  "read_only_rootfs": true,
  "privileged": false,
  "configured_user": "nonroot",
  "command_shape": ["exe:nginx", "flag:-g", "<flag-value>"],
  "entrypoint_shape": ["exe:docker-entrypoint.sh"],
  "schema_version": "porygon.runtime-context.v1"
}
```

```json context-example-security-change
{
  "schema_version": "porygon.runtime-context.v1",
  "entrypoint_shape": ["exe:docker-entrypoint.sh"],
  "command_shape": ["exe:nginx", "flag:-g", "<flag-value>"],
  "configured_user": "nonroot",
  "privileged": true,
  "read_only_rootfs": true,
  "network_mode": "bridge",
  "capabilities": {"add": ["NET_BIND_SERVICE", "CHOWN"], "drop": ["SYS_ADMIN"]},
  "devices": [],
  "ports": [
    {"container_port": 8080, "protocol": "tcp", "binding_scope": "loopback", "host_port_mode": "ephemeral"}
  ],
  "mounts": [
    {"destination": "/cache", "type": "volume", "read_only": false},
    {"destination": "/etc/nginx/conf.d", "type": "bind", "read_only": true}
  ]
}
```

## Fragmentation and support rules

Each digest-plus-context fit stratum requires at least 10 independent complete
fit runs, at least three same-digest replicas, and the frozen minimum evidence
quality from Plan 004. Calibration requires 10 different complete runs. No run,
container, or overlapping window may occur in more than one split.

If a primary test context lacks support, `ARM-CONTEXT` returns
`insufficient_profile`; it does not borrow a digest-only profile. Report
`MET-INSUF-001` with a confidence interval and include insufficient results in
the arm denominator. Excessive fragmentation is a valid negative outcome.

## Drift and leakage rules

- Tag profiles use the literal recorded tag; resolved digest is retained to
  reveal drift. Test-time tag resolution never rewrites a fitted tag profile.
- Digest profiles require the exact frozen digest.
- Context profiles require the exact digest and context hash.
- Run assignment is computed from run ID before execution. Every window from
  one run inherits that run's split.
- Replicas from one complete run cannot be treated as independent windows.
- Hyperparameters and thresholds are frozen after pilot/calibration and before
  confirmatory execution.
