# Catbird MLS Chat Integration Project

Private, end-to-end encrypted group chat using MLS (Messaging Layer Security) and AT Protocol identity, integrated into the Catbird iOS app.

## 🎯 Project Goal

Fork Catbird into `mls-chat` branch and integrate production-ready MLS E2EE group chat alongside existing Bluesky chat, with complete:
- ✅ Lexicon definitions (AT Protocol)
- ✅ Swift models generated via Petrel
- ✅ Rust backend server
- ✅ iOS client integration
- ✅ End-to-end encryption (MLS 1.0)
- ✅ Self-hostable infrastructure

## 📋 Documentation

**Start here for complete understanding:**

### Master Planning Documents
1. **[EXECUTIVE_SUMMARY.md](EXECUTIVE_SUMMARY.md)** ⭐ **START HERE**
   - Project overview and quickstart
   - Architecture diagram
   - Success criteria
   - 14-day timeline

2. **[MLS_INTEGRATION_MASTER_PLAN.md](MLS_INTEGRATION_MASTER_PLAN.md)**
   - Comprehensive 30-page technical plan
   - 5 phases with detailed specifications
   - Lexicon schemas
   - API endpoints
   - Security analysis
   - Dependencies and workflows

3. **[MLS_TASK_LIST.md](MLS_TASK_LIST.md)**
   - 200+ granular tasks
   - Time estimates per task
   - Dependencies and blockers
   - Success criteria
   - Agent assignments

4. **[AGENTIC_WORKFLOWS.md](AGENTIC_WORKFLOWS.md)**
   - 14+ specialized agent specifications
   - Coordination protocol
   - Communication channels
   - Quality gates
   - Conflict resolution

### 🚀 Greenfield Implementation (Ready to Build)

**[GREENFIELD_IMPLEMENTATION_SUMMARY.md](GREENFIELD_IMPLEMENTATION_SUMMARY.md)** ⭐ **START HERE FOR IMPLEMENTATION**
- Complete greenfield implementation (no legacy code, no migrations)
- Ready-to-use deliverables:
  - ✅ Database schema (`server/schema_greenfield.sql`) - 650 lines
  - ✅ Swift client code (`Catbird/Services/MLS/MLSIdentityBackup.swift`) - 450 lines
  - ✅ Server automatic rejoin (`server/src/automatic_rejoin.rs`) - 400 lines
  - ✅ Server admin system (`server/src/admin_system.rs`) - 500 lines
  - ✅ All 22 lexicons defined
- 5-week implementation roadmap with week-by-week tasks
- Open questions and recommendations
- Complete testing checklist

### ⭐ Security & Admin System (Architecture)

**[MLS_COMPLETE_IMPLEMENTATION_GUIDE.md](MLS_COMPLETE_IMPLEMENTATION_GUIDE.md)** ⭐ **COMPREHENSIVE ARCHITECTURE GUIDE**
- Complete architecture for E2EE group chat
- Answers critical questions:
  - ❌ Can admins delete messages? → NO (E2EE impossible)
  - ✅ iCloud Keychain backup? → YES (identity only, ~500 bytes)
  - ✅ Automatic rejoin? → YES (no admin approval needed)
- Architectural decisions and security analysis
- Full database design documentation
- All lexicon specifications
- **Reference guide - see GREENFIELD_IMPLEMENTATION_SUMMARY.md for implementation**

**Supporting Security Documents:**
- [SECURITY_ADMIN_COMPLETE_PLAN.md](SECURITY_ADMIN_COMPLETE_PLAN.md) - Original admin system plan
- [ADMIN_SECURITY_PLAN.md](ADMIN_SECURITY_PLAN.md) - Admin architecture deep-dive
- [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) - Sender identity security analysis
- [QUICK_SECURITY_SUMMARY.md](QUICK_SECURITY_SUMMARY.md) - Quick reference
- [BLUESKY_BLOCKS_INTEGRATION.md](BLUESKY_BLOCKS_INTEGRATION.md) - Blocks enforcement

### Existing Technical Docs
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** - System design and data flow
- **[docs/SECURITY.md](docs/SECURITY.md)** - Threat model and mitigations
- **[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)** - Developer workflow
- **[SETUP.md](SETUP.md)** - Current implementation status
- **[COMPLETED.md](COMPLETED.md)** - What's been built so far

## 🚀 Quick Start

### For Project Managers
```bash
# Read the executive summary
cat EXECUTIVE_SUMMARY.md

# Review the master plan
cat MLS_INTEGRATION_MASTER_PLAN.md

# Check the task breakdown
cat MLS_TASK_LIST.md

# Set up GitHub Project with all tasks
gh project create "MLS Chat Integration"
```

### For Developers
```bash
# 1. Review current state
cat COMPLETED.md

# 2. Check your assigned agent role
cat AGENTIC_WORKFLOWS.md  # Find your agent

# 3. Start Phase 1 work
cd /Users/joshlacalamito/Developer/Catbird+Petrel/Catbird
git checkout -b mls-chat

# 4. Follow MLS_TASK_LIST.md for your tasks
```

### For Architects
```bash
# Review the complete technical design
cat MLS_INTEGRATION_MASTER_PLAN.md

# Check lexicon specifications (Phase 1 Task P1.2)
ls -la lexicon/

# Review current server implementation
cd server && cat src/handlers.rs
```

## 📊 Project Metrics

- **Timeline**: 14 days (with parallelization)
- **Total Effort**: 129 agent-hours
- **Agents**: 14 specialized roles
- **Tasks**: 200+ granular items
- **Phases**: 5 major phases
- **Deliverables**: Production-ready MLS chat in Catbird

## 🏗️ Project Structure

```
Catbird+Petrel/
├── mls/                           # This directory (MLS backend & planning)
│   ├── EXECUTIVE_SUMMARY.md       ⭐ START HERE
│   ├── MLS_INTEGRATION_MASTER_PLAN.md  # 30-page spec
│   ├── MLS_TASK_LIST.md           # 200+ tasks
│   ├── AGENTIC_WORKFLOWS.md       # Agent coordination
│   ├── server/                    # Rust backend (Axum + Postgres)
│   ├── mls-ffi/                   # Rust FFI for iOS
│   ├── lexicon/                   # AT Protocol lexicons
│   ├── client-ios/                # iOS reference implementation
│   └── docs/                      # Technical documentation
└── Catbird/                       # Main iOS app (to fork into mls-chat branch)
    └── [mls-chat branch]          # Integration target
```

## 🎯 Phases Overview

### Phase 1: Preparation (2 days)
- Create `mls-chat` branch
- Complete 10 AT Protocol lexicon definitions
- Audit existing Catbird architecture
- **Output**: Ready for code generation

### Phase 2: Code Generation (2 days)
- Generate Swift models via Petrel
- Implement MLSClient (Swift API client)
- Complete OpenMLS FFI (Rust crypto)
- **Output**: Models and crypto layer

### Phase 3: Server (3 days)
- JWT authentication
- PostgreSQL schema + migrations
- Complete all 9 API handlers
- Production hardening (Docker, TLS, metrics)
- **Output**: Production server

### Phase 4: iOS Integration (5 days)
- FFI bridge (Swift ↔ Rust)
- Keychain + SwiftData storage
- View models + SwiftUI views
- Integration into Catbird app
- **Output**: Complete iOS app

### Phase 5: Testing & Deployment (2 days)
- End-to-end testing (10+ scenarios)
- Security audit
- Documentation site
- Production deployment
- **Output**: Beta-ready system

## 🤖 Agentic Approach

This project uses **14 specialized agents** working in parallel where possible:

1. Git Coordinator
2. Lexicon Architect
3. Code Archaeologist
4. Petrel Operator
5. Network Engineer (Swift)
6. Cryptography Specialist (Rust)
7. Backend Engineer
8. QA Engineer
9. FFI Specialist
10. Security Engineer
11. iOS Developer
12. UI Developer
13. Integration Specialist
14. Security Auditor
15. Tech Writer
16. DevOps Engineer

See **[AGENTIC_WORKFLOWS.md](AGENTIC_WORKFLOWS.md)** for full specifications.

## ✅ Success Criteria

From the Deep Research MVP plan:

- 📌 DID key publication (clients can verify MLS keys)
- 📌 KeyPackage fetch and rotation working
- 📌 Full E2E flow: create → invite → send → decrypt (3+ members)
- 📌 Post-compromise security (PCS) after member removal
- 📌 No PII/plaintext in logs
- 📌 Encrypted attachments with integrity checks
- 📌 Failure modes handled (stale epoch, wrong ciphersuite, etc.)

## 🔐 Security Highlights

### Encrypted
- ✅ All message content (MLS)
- ✅ All attachments (client-side)
- ✅ MLS group state (local storage)

### Visible to Server
- ⚠️ Conversation IDs (opaque UUIDs)
- ⚠️ Member DIDs (not on public ATProto)
- ⚠️ Message timing/sizes
- ⚠️ Epoch numbers

### Threat Model
- **Server compromise**: No plaintext exposed
- **Client compromise**: PCS via member removal
- **Network eavesdrop**: TLS + MLS double encryption

See **[docs/SECURITY.md](docs/SECURITY.md)** for full analysis.

## 🏁 Current Status

**Infrastructure**: ✅ Complete (see [COMPLETED.md](COMPLETED.md))
- Server implements 8 XRPC endpoints with database-backed logic
- FFI defined (C-compatible API)
- Basic tests passing
- Documentation framework ready

**Next**: Begin Phase 1 execution per **[MLS_TASK_LIST.md](MLS_TASK_LIST.md)**

## 🔗 Key Resources

### External
- [MLS RFC 9420](https://datatracker.ietf.org/doc/rfc9420/)
- [OpenMLS Documentation](https://openmls.tech/)
- [AT Protocol Specs](https://atproto.com/)

### Internal
- All planning docs in this directory (`mls/`)
- Catbird source code: `../Catbird/`
- Petrel generator: `../Petrel/` (assumed)

## 🚀 Getting Started

1. **Review**: Read [EXECUTIVE_SUMMARY.md](EXECUTIVE_SUMMARY.md) (10 min)
2. **Plan**: Review [MLS_INTEGRATION_MASTER_PLAN.md](MLS_INTEGRATION_MASTER_PLAN.md) (1 hour)
3. **Assign**: Match team members to agents in [AGENTIC_WORKFLOWS.md](AGENTIC_WORKFLOWS.md)
4. **Execute**: Follow [MLS_TASK_LIST.md](MLS_TASK_LIST.md) task-by-task
5. **Track**: Use GitHub Project board with all 200+ tasks

## 💬 Communication

- **Daily Standup**: Async, 9:00 AM (see AGENTIC_WORKFLOWS.md)
- **Code Reviews**: 4-hour turnaround
- **Urgent Issues**: #mls-urgent channel
- **Master Controller**: Tracks progress, resolves blockers

## 📞 Questions?

- **Technical**: See [MLS_INTEGRATION_MASTER_PLAN.md](MLS_INTEGRATION_MASTER_PLAN.md)
- **Tasks**: See [MLS_TASK_LIST.md](MLS_TASK_LIST.md)
- **Workflow**: See [AGENTIC_WORKFLOWS.md](AGENTIC_WORKFLOWS.md)
- **Architecture**: See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- **Security**: See [docs/SECURITY.md](docs/SECURITY.md)

## License

MIT

---

**Project Status**: 🟢 **Ready to Execute**  
**Version**: 1.0  
**Last Updated**: October 21, 2025  

*Let's build the future of private messaging.* 🔐🚀


## XRPC Proxy via PDS

This service validates inter-service JWTs (at+jwt) from the PDS when proxying.
- Set `SERVICE_DID` to this service's DID.
- Optionally set `PDS_XRPC_BASE` to enable fallback proxying for non-MLS endpoints (disabled by default).
- Local DS nodes do not provide a shim for `/xrpc/com.atproto.repo.getRecord` (expect HTTP 404).
- Federation discovery must resolve user DID documents to a real PDS/AppView and fetch `blue.catbird.mls.profile` there.

## 🐳 Docker Deployment (Current)

**As of October 23, 2025**, the MLS server now runs using Docker Compose for improved isolation, portability, and management.

### Quick Start
```bash
cd /home/ubuntu/mls/server
sudo docker compose --env-file .env.docker up -d
```

### Access
- **Health Check**: http://localhost:3000/health
- **API Endpoints**: http://localhost:3000/xrpc/*

### Management
```bash
# View status
sudo docker compose ps

# View logs
sudo docker logs -f catbird-mls-server

# Restart
sudo docker compose restart

# Stop
sudo docker compose down
```

### Documentation
- 📚 **Full Migration Guide**: [DOCKER_MIGRATION_SUMMARY.md](DOCKER_MIGRATION_SUMMARY.md)
- ⚡ **Quick Reference**: [DOCKER_QUICKSTART.md](DOCKER_QUICKSTART.md)
- 📖 **Original Setup Guide**: [SERVER_SETUP.md](SERVER_SETUP.md) (legacy systemd approach)
