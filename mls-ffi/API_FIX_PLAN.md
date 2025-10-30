# API.rs Fix Plan

## Current Situation
The agents added extensive OpenMLS compliance features, but used OpenMLS APIs that don't exist in v0.6.

## Options

### Option 1: Fix All Agent Code (Complex)
Fix every OpenMLS API call to work with v0.6:
- Fix ProposalRef imports
- Fix Credential API (no `.identity()` method)
- Fix StagedCommit API (no `.epoch()` method)  
- Fix WireFormatPolicy usage (use constants, not constructors)
- Add hash computation for KeyPackageResult
- Fix type conversions

**Pros**: Keeps all compliance features
**Cons**: Time-consuming, need to research OpenMLS 0.6 API docs

### Option 2: Incremental Approach (Recommended)
Start with working baseline, add one feature at a time:
1. Get current code compiling
2. Add forward secrecy config (simple)
3. Add credential validation (moderate)
4. Add proposal inspection (complex)
5. Test each addition

**Pros**: Always have working code, easier to debug
**Cons**: Features added gradually

### Option 3: Simplified Compliance
Implement OpenMLS compliance with minimal code changes:
- Add config passing (already mostly done)
- Add basic validation hooks
- Document where app-level validation goes
- Leave complex features for later

**Pros**: Fast path to working XCFramework
**Cons**: Not all compliance features immediately available

## Recommendation
**Option 2** - Incremental approach. Let's:
1. Get basic FFI compiling NOW
2. Rebuild XCFramework 
3. Add compliance features one by one with tests
