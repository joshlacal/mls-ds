# Privacy Decisions

## PRIV-001: Do not persist plaintext message sender identity

Status: accepted

### Decision
For the `messages` table, the `sender_did` column is intentionally written as `NULL` for new app and commit messages.

### Why
- Sender identity is already derivable by authorized clients from MLS-decrypted payload/context.
- Persisting plaintext sender metadata increases exposure in logs, DB snapshots, analytics, and incident tooling.
- Server-side routing/fanout/unread logic uses authenticated caller identity at runtime, not persisted plaintext sender metadata in message rows.

### Scope
Applies to message persistence paths (app/commit rows in `messages`).

### Non-scope
Does **not** apply to non-message domains that require sender identity as first-class business data, including:
- chat requests (`chat_requests.sender_did`)
- per-sender rate limiting and abuse controls
- runtime fanout and notification exclusion logic

### Implementation convention
When writing `messages.sender_did`, use:
- `Option::<&str>::None` and a short reference comment:
  `// sender_did intentionally NULL — PRIV-001 (docs/PRIVACY.md)`

### Schema note
`sender_did` remains nullable for compatibility and staged migration; privacy behavior is enforced in write paths.
