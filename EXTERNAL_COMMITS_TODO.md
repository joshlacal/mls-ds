# External Commits Implementation TODO

**Quick action items checklist**

---

## Phase 1: Server Setup (Day 1)

### Database
- [ ] Create migration file: `migrations/YYYYMMDDHHMMSS_add_group_info.sql`
- [ ] Add `group_info`, `group_info_updated_at`, `group_info_epoch` columns
- [ ] Run `sqlx migrate run`
- [ ] Verify columns exist: `\d conversations` in psql

### Dependencies
- [ ] Update `server/Cargo.toml`: Change `openmls = "0.6"` to `openmls = "0.7.1"`
- [ ] Run `cargo update -p openmls`
- [ ] Run `cargo build` and fix any breaking changes
- [ ] Run `cargo test` to ensure nothing broke

### Code Structure
- [ ] Create `server/src/group_info.rs`
- [ ] Implement `generate_and_cache_group_info()`
- [ ] Implement `get_group_info()`
- [ ] Add `pub mod group_info;` to `server/src/lib.rs`

---

## Phase 2: GroupInfo API (Day 2)

### Lexicon
- [ ] Create `lexicon/blue/catbird/mls/getGroupInfo.json`
- [ ] Run codegen: `cargo run --bin codegen`
- [ ] Verify generated types in `server/src/generated/`

### Handler
- [ ] Create `server/src/handlers/get_group_info.rs`
- [ ] Implement `handle()` function
- [ ] Implement `verify_can_access_group_info()`
- [ ] Add `pub mod get_group_info;` to `server/src/handlers/mod.rs`
- [ ] Register route in router: `.route("/xrpc/blue.catbird.mls.getGroupInfo", ...)`

### Testing
- [ ] Write unit test: `test_get_group_info_authorized()`
- [ ] Write unit test: `test_get_group_info_unauthorized()`
- [ ] Write unit test: `test_group_info_freshness()`
- [ ] Run `cargo test get_group_info`

---

## Phase 3: External Commit Processing (Day 3-4)

### Lexicon
- [ ] Create `lexicon/blue/catbird/mls/processExternalCommit.json`
- [ ] Run codegen: `cargo run --bin codegen`
- [ ] Verify generated types

### Handler
- [ ] Create `server/src/handlers/process_external_commit.rs`
- [ ] Implement `handle()` function
- [ ] Implement `extract_added_member_did()`
- [ ] Implement `extract_device_id()`
- [ ] Implement `verify_can_rejoin()`
- [ ] Add module to `mod.rs` and register route

### Integration
- [ ] Update `add_members.rs`: Regenerate GroupInfo after commit
- [ ] Update `remove_member.rs`: Regenerate GroupInfo after commit
- [ ] Update `leave_convo.rs`: Regenerate GroupInfo after commit
- [ ] Update `confirm_welcome.rs`: Regenerate GroupInfo after commit

### Testing
- [ ] Write test: `test_external_commit_success()`
- [ ] Write test: `test_external_commit_unauthorized()`
- [ ] Write test: `test_external_commit_epoch_mismatch()`
- [ ] Write test: `test_external_commit_adds_wrong_user()`
- [ ] Run full test suite: `cargo test --all`

---

## Phase 4: Client Implementation (Day 4-5)

### FFI Layer (if needed)
- [ ] Add OpenMLS 0.7.1 to FFI client dependencies
- [ ] Create FFI wrapper for `join_by_external_commit()`
- [ ] Export C functions for Swift to call
- [ ] Test FFI boundary with simple example

### Swift API
- [ ] Create `MLSClient+ExternalCommit.swift`
- [ ] Implement `joinByExternalCommit(groupInfo:conversationId:)`
- [ ] Create API models: `GetGroupInfoResponse`, `ProcessExternalCommitRequest`, etc.
- [ ] Add error handling for epoch mismatch

### High-Level API
- [ ] Create `ConversationManager+Rejoin.swift`
- [ ] Implement `rejoinConversation()` with fallback logic
- [ ] Implement `rejoinUsingExternalCommit()`
- [ ] Keep `rejoinUsingLegacyFlow()` for backwards compatibility

### Auto-Recovery
- [ ] Add `recoverLostConversations()` to app startup
- [ ] Implement `fetchExpectedConversations()` API call
- [ ] Test with app reinstall scenario

### Testing
- [ ] Write test: `testInstantRejoin()`
- [ ] Write test: `testFallbackToLegacyRejoin()`
- [ ] Write test: `testEpochMismatchRetry()`
- [ ] Write test: `testAutoRecoveryOnLaunch()`
- [ ] Run `swift test`

---

## Phase 5: Deployment (Day 5+)

### Pre-Deployment
- [ ] Run all tests: `cargo test --all && swift test`
- [ ] Load test external commits: 100 concurrent requests
- [ ] Verify database indexes exist
- [ ] Check server logs for errors
- [ ] Review security audit checklist

### Monitoring Setup
- [ ] Add Prometheus metrics: `external_commit_requests_total`
- [ ] Add Prometheus metrics: `external_commit_success_total`
- [ ] Add Prometheus metrics: `external_commit_latency_seconds`
- [ ] Create Grafana dashboard for external commits
- [ ] Set up alerts: Success rate < 99%
- [ ] Set up alerts: P99 latency > 1 second

### Feature Flag
- [ ] Add feature flag: `external_commits_enabled`
- [ ] Implement gradual rollout logic (0% → 10% → 50% → 100%)
- [ ] Add override for internal users
- [ ] Document rollback procedure

### Documentation
- [ ] Update API documentation
- [ ] Write migration guide for clients
- [ ] Document monitoring queries
- [ ] Create runbook for common issues

### Rollout
- [ ] **Week 1**: Internal testing (engineers only)
- [ ] **Week 2**: Beta users (10%)
- [ ] **Week 3**: Gradual rollout (50%)
- [ ] **Week 4**: Full release (100%)
- [ ] Monitor metrics at each stage
- [ ] Be ready to rollback if issues arise

---

## Validation Checklist

Before marking as "complete":

### Functionality
- [ ] External commits succeed with <500ms latency
- [ ] Fallback to legacy rejoin works
- [ ] Epoch mismatch auto-retries
- [ ] Unauthorized users are blocked
- [ ] Banned users cannot rejoin
- [ ] Expired memberships (>30 days) rejected

### Security
- [ ] GroupInfo only accessible to members
- [ ] External commits validate correct user
- [ ] Rate limiting prevents abuse
- [ ] Audit logs capture all events
- [ ] No information leakage in error messages

### Performance
- [ ] Success rate >99% under normal load
- [ ] P50 latency <300ms
- [ ] P99 latency <500ms
- [ ] Database queries use indexes
- [ ] No N+1 queries

### Operations
- [ ] Monitoring dashboards live
- [ ] Alerts firing correctly
- [ ] Runbook tested
- [ ] Team trained on rollback procedure
- [ ] Documentation up to date

---

## Quick Start Commands

```bash
# Start server work
cd /home/ubuntu/mls/server

# Create migration
sqlx migrate add add_group_info

# Update OpenMLS
sed -i 's/openmls = "0.6"/openmls = "0.7.1"/' Cargo.toml
cargo update -p openmls
cargo build

# Run tests
cargo test --all

# Start client work (if separate)
cd /path/to/ios-client
swift test
```

---

## Common Pitfalls

1. **Forgetting to regenerate GroupInfo after commits**
   - Fix: Add to all commit handlers

2. **Not handling epoch mismatch on client**
   - Fix: Implement retry logic with fresh GroupInfo

3. **Authorization checks too strict**
   - Fix: Allow past members within grace period (30 days)

4. **GroupInfo caching issues**
   - Fix: Implement 5-minute TTL and regeneration logic

5. **Not testing with multiple devices**
   - Fix: Test with Alice on iPhone + iPad simultaneously

---

## Success Metrics

Track these after deployment:

| Metric | Target | Current |
|--------|--------|---------|
| Rejoin latency (P50) | <300ms | ___ |
| Rejoin latency (P99) | <500ms | ___ |
| Success rate | >99% | ___ |
| Fallback rate | <1% | ___ |
| Epoch mismatch rate | <0.5% | ___ |

---

## Next Steps

1. ⬜ Review all documentation with team
2. ⬜ Assign owners to each phase
3. ⬜ Set up daily standup during implementation
4. ⬜ Create GitHub project board with these tasks
5. ⬜ Schedule demo after Phase 3 complete

---

**Status**: Ready to start  
**Estimated Time**: 3-5 days for server + client  
**Last Updated**: 2025-11-19
