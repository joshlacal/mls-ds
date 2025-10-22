# MLS Chat Integration - Git Setup Documentation

**Date:** 2025-10-21  
**Repository:** joshlacal/Catbird  
**Branch:** mls-chat

## Overview

This document captures the complete setup of the `mls-chat` branch and GitHub project board for integrating MLS E2EE group chat into the Catbird iOS app.

---

## 1. Branch Setup

### Branch Information
- **Branch Name:** `mls-chat`
- **Source:** `main` branch
- **Created From Commit:** `5ec0485` - "docs: Update moderation implementation status to 100% complete"
- **Branch URL:** https://github.com/joshlacal/Catbird/tree/mls-chat

### Initial Tag
- **Tag Name:** `mls-chat-init`
- **Commit:** `5ec0485`
- **Tag URL:** https://github.com/joshlacal/Catbird/releases/tag/mls-chat-init
- **Purpose:** Marks the starting point for MLS integration work

### Branch Protection Rules

✅ **Active Protection Settings:**
- **Require PR reviews:** 1 approving review required
- **Dismiss stale reviews:** Enabled (new commits dismiss old approvals)
- **Code owner reviews:** Not required
- **Force pushes:** Disabled
- **Branch deletions:** Disabled
- **Linear history:** Not required
- **Admin enforcement:** Disabled (admins can bypass)

**Settings URL:** https://github.com/joshlacal/Catbird/settings/branch_protection_rules

---

## 2. GitHub Milestones

All milestones have been created in the repository:

| # | Title | Description | URL |
|---|-------|-------------|-----|
| 1 | Milestone 1: Lexicons Complete | All lexicons validated, architecture documented, branch ready | https://github.com/joshlacal/Catbird/milestone/1 |
| 2 | Milestone 2: Code Generation Complete | Swift models generated, MLSClient implemented, FFI compiling | https://github.com/joshlacal/Catbird/milestone/2 |
| 3 | Milestone 3: Server Production Ready | All endpoints working, database deployed, Docker built | https://github.com/joshlacal/Catbird/milestone/3 |
| 4 | Milestone 4: iOS App Complete | All views implemented, integrated into Catbird, regression passing | https://github.com/joshlacal/Catbird/milestone/4 |
| 5 | Milestone 5: Production Deployment | E2E tests passing, security audit complete, beta deployed | https://github.com/joshlacal/Catbird/milestone/5 |

**Milestones URL:** https://github.com/joshlacal/Catbird/milestones

---

## 3. GitHub Labels

The following labels have been created for task organization:

| Label | Color | Purpose |
|-------|-------|---------|
| `phase-1-prep` | ![#0366d6](https://via.placeholder.com/15/0366d6/000000?text=+) `#0366d6` | Phase 1: Preparation tasks |
| `phase-2-codegen` | ![#5319e7](https://via.placeholder.com/15/5319e7/000000?text=+) `#5319e7` | Phase 2: Code generation tasks |
| `phase-3-server` | ![#d73a4a](https://via.placeholder.com/15/d73a4a/000000?text=+) `#d73a4a` | Phase 3: Server implementation |
| `phase-4-ios` | ![#fbca04](https://via.placeholder.com/15/fbca04/000000?text=+) `#fbca04` | Phase 4: iOS integration |
| `phase-5-testing` | ![#0e8a16](https://via.placeholder.com/15/0e8a16/000000?text=+) `#0e8a16` | Phase 5: Testing & deployment |
| `critical-path` | ![#b60205](https://via.placeholder.com/15/b60205/000000?text=+) `#b60205` | Critical path items (blockers) |
| `parallelizable` | ![#c5def5](https://via.placeholder.com/15/c5def5/000000?text=+) `#c5def5` | Can be worked on in parallel |
| `blocked` | ![#e99695](https://via.placeholder.com/15/e99695/000000?text=+) `#e99695` | Blocked by dependencies |
| `security` | ![#d93f0b](https://via.placeholder.com/15/d93f0b/000000?text=+) `#d93f0b` | Security-sensitive work |

**Labels URL:** https://github.com/joshlacal/Catbird/labels

---

## 4. GitHub Project Board

### Project Setup Instructions

**Note:** GitHub Projects (v2) require additional OAuth scopes that need interactive authentication. The project board should be created manually via the web interface or with proper authentication.

### Manual Creation Steps:

1. **Navigate to:** https://github.com/joshlacal/Catbird/projects
2. **Click:** "New project"
3. **Configure:**
   - **Name:** Catbird MLS Chat Integration
   - **Description:** 14-day project to integrate MLS E2EE group chat into Catbird iOS app
   - **Template:** Board (or start from scratch)

4. **Create Columns:**
   - 📋 Backlog
   - 🔜 Ready
   - 🏗️ In Progress
   - 👀 Review
   - ✅ Done

5. **Link Milestones:** Associate milestones 1-5 with the project
6. **Add Issues:** Create issues from `GITHUB_PROJECT_TEMPLATE.yaml` (see section 5)

### Alternative: Use GitHub CLI (requires auth)

```bash
# Refresh authentication with project scopes
gh auth refresh -s project,read:project,write:project

# Create project
gh project create --owner joshlacal --title "Catbird MLS Chat Integration"
```

**Projects URL:** https://github.com/joshlacal/Catbird/projects

---

## 5. Creating Issues from Template

The `GITHUB_PROJECT_TEMPLATE.yaml` file in the mls repository contains all issue definitions. To create issues:

### Using GitHub CLI:

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel/mls

# Example: Create P1.1 issue
gh issue create \
  --repo joshlacal/Catbird \
  --title "P1.1: Git & Repository Setup" \
  --milestone "Milestone 1: Lexicons Complete" \
  --label "phase-1-prep,critical-path" \
  --body "$(cat <<'EOF'
**Task**: Create mls-chat branch and set up project board

Checklist:
- [x] Create mls-chat branch from main
- [x] Set up branch protection rules
- [ ] Create GitHub Project board
- [x] Tag initial commit
- [ ] Configure CI/CD for branch

**Deliverable**: Branch ready for development
**Blockers**: None

See: MLS_TASK_LIST.md#p11
EOF
)"
```

### Bulk Creation Script:

A script can be created to parse `GITHUB_PROJECT_TEMPLATE.yaml` and create all issues programmatically.

**Issues URL:** https://github.com/joshlacal/Catbird/issues

---

## 6. Quick Reference URLs

### Repository & Branch
- **Repository:** https://github.com/joshlacal/Catbird
- **Main Branch:** https://github.com/joshlacal/Catbird/tree/main
- **MLS Chat Branch:** https://github.com/joshlacal/Catbird/tree/mls-chat
- **Branch Comparison:** https://github.com/joshlacal/Catbird/compare/main...mls-chat

### Settings & Configuration
- **Branch Protection:** https://github.com/joshlacal/Catbird/settings/branch_protection_rules
- **Repository Settings:** https://github.com/joshlacal/Catbird/settings

### Project Management
- **Milestones:** https://github.com/joshlacal/Catbird/milestones
- **Labels:** https://github.com/joshlacal/Catbird/labels
- **Issues:** https://github.com/joshlacal/Catbird/issues
- **Pull Requests:** https://github.com/joshlacal/Catbird/pulls
- **Projects:** https://github.com/joshlacal/Catbird/projects

### Tags & Releases
- **Initial Tag:** https://github.com/joshlacal/Catbird/releases/tag/mls-chat-init
- **All Tags:** https://github.com/joshlacal/Catbird/tags
- **Releases:** https://github.com/joshlacal/Catbird/releases

---

## 7. Local Development Setup

### Clone and Switch to Branch

```bash
# If not already cloned
git clone https://github.com/joshlacal/Catbird.git
cd Catbird

# Switch to mls-chat branch
git checkout mls-chat

# Verify branch protection
gh api repos/joshlacal/Catbird/branches/mls-chat/protection
```

### Verify Setup

```bash
# Check branch
git branch -vv

# View branch protection
gh api repos/joshlacal/Catbird/branches/mls-chat/protection | jq

# List milestones
gh api repos/joshlacal/Catbird/milestones | jq '.[] | {number, title}'

# List labels
gh api repos/joshlacal/Catbird/labels | jq '.[] | {name, color}' | head -20
```

---

## 8. Development Workflow

### Creating Pull Requests

1. Create feature branch from `mls-chat`:
   ```bash
   git checkout mls-chat
   git pull origin mls-chat
   git checkout -b feature/your-feature-name
   ```

2. Make changes and commit:
   ```bash
   git add .
   git commit -m "feat: your feature description"
   git push origin feature/your-feature-name
   ```

3. Create PR to `mls-chat` branch:
   ```bash
   gh pr create \
     --base mls-chat \
     --title "feat: Your Feature Title" \
     --body "Description of changes" \
     --label "phase-X-name"
   ```

4. PR will require 1 approving review before merge

### Linking Issues and PRs

Use keywords in PR descriptions to link to issues:
- `Closes #123` - Closes issue when PR is merged
- `Fixes #123` - Same as closes
- `Resolves #123` - Same as closes
- `Relates to #123` - Links without closing

---

## 9. CI/CD Configuration

### GitHub Actions

Current CI/CD setup should be verified and potentially extended for the `mls-chat` branch:

**TODO:**
- [ ] Review existing workflows in `.github/workflows/`
- [ ] Ensure workflows run on `mls-chat` branch
- [ ] Add MLS-specific tests to CI pipeline
- [ ] Configure build checks as required status checks

**Workflows URL:** https://github.com/joshlacal/Catbird/actions

---

## 10. Next Steps

### Immediate Tasks

1. **Create GitHub Project Board** (manual or via CLI with auth)
2. **Create Initial Issues** from `GITHUB_PROJECT_TEMPLATE.yaml`
3. **Configure CI/CD** for mls-chat branch
4. **Begin Phase 1 Tasks:**
   - P1.1: Git & Repository Setup ✅ (Complete)
   - P1.2: Complete Lexicon Definitions
   - P1.3: Catbird Architecture Audit

### Phase 1 Deliverables (Day 1-2)

- ✅ Branch created and protected
- ✅ Milestones defined
- ✅ Labels created
- ✅ Initial commit tagged
- 🔲 Project board set up
- 🔲 All 10 lexicon files completed
- 🔲 Architecture documentation complete
- 🔲 Integration plan finalized

---

## 11. Support & Documentation

### Related Documentation
- **MLS Integration Master Plan:** `/Users/joshlacalamito/Developer/Catbird+Petrel/mls/MLS_INTEGRATION_MASTER_PLAN.md`
- **Task List:** `/Users/joshlacalamito/Developer/Catbird+Petrel/mls/MLS_TASK_LIST.md`
- **Project Template:** `/Users/joshlacalamito/Developer/Catbird+Petrel/mls/GITHUB_PROJECT_TEMPLATE.yaml`
- **Parallel Agents Guide:** `/Users/joshlacalamito/Developer/Catbird+Petrel/mls/PARALLEL_AGENTS_GUIDE.md`

### GitHub CLI Commands Reference

```bash
# Branch info
gh api repos/joshlacal/Catbird/branches/mls-chat

# Create issue
gh issue create --repo joshlacal/Catbird --title "Title" --body "Body"

# Create PR
gh pr create --base mls-chat --title "Title"

# View milestones
gh api repos/joshlacal/Catbird/milestones

# View project
gh project list --owner joshlacal
```

---

## 12. Summary

### ✅ Completed Setup

- [x] `mls-chat` branch created from `main`
- [x] Branch protection rules configured (1 required review)
- [x] Initial commit tagged as `mls-chat-init`
- [x] 5 milestones created
- [x] 9 project labels created
- [x] Documentation complete

### 🔲 Manual Steps Required

- [ ] Create GitHub Project board (requires authentication)
- [ ] Create issues from template
- [ ] Configure CI/CD for branch
- [ ] Set up project automation

### 📊 Statistics

- **Milestones:** 5
- **Labels:** 9
- **Branch Protection Rules:** Active
- **Initial Tag:** mls-chat-init (commit 5ec0485)

---

**Document Version:** 1.0  
**Last Updated:** 2025-10-21  
**Maintained By:** MLS Integration Team
