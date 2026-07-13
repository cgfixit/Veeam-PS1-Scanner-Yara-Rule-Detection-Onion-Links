---
name: optimize
description: >-
  description: Use for concise generic optimization of existing code repositories. Applies battle-tested patterns to cut technical debt, boost performance, maintainability and security in live codebases across languages. Trigger on audits, refactors, optimization requests or reviews of established repos not greenfield projects.
  Veeam-PS1-Scanner-Yara-Rule-Detection-Onion-Links. Use when asked to clean up
  the scanner architecture, simplify the rule workflow, or run a measured
  optimization loop with verification, review, commits, and tracker updates.
---

# optimize

--

# Optimizer Codex

Apply these principles to **existing** code repositories. Focus on high-impact, low-risk improvements that compound over time.

## Core Principles
- **Measure first**: Establish baselines (test pass rate, coverage, benchmarks, bundle size, p99 latency) before any change.
- **Delete > Optimize**: Remove dead code, unused dependencies, redundant logic. The fastest code is code that never executes.
- **Small verifiable steps**: One concern per PR/commit. Always pair with tests or contract verification. Prefer reversible changes.
- **Pareto 80/20**: Identify the 20% of files/functions causing 80% of pain (complexity, runtime, change churn, support tickets).
- **Preserve observable behavior**: Refactors must not alter external contracts unless requirements explicitly change. Use golden tests or contract tests.

## High-Impact Optimization Vectors
**Bloat & Dependency Hygiene**
- Audit manifests (package.json, requirements.txt, go.mod, Cargo.toml) for unused packages using depcheck / unused / cargo-udeps equivalents.
- Replace heavy transitive dependencies with lighter stdlib alternatives or focused micro-libraries.
- Enable automated updates (Renovate/Dependabot) with strict policies; pin versions.

**Duplication & Complexity**
- Run linters + complexity tools; target functions/classes >50-100 LOC or cyclomatic complexity >10.
- Extract repeated logic into shared modules, utilities, or domain services.
- Apply "extract method" and "replace conditional with polymorphism" where it reduces branching.

**Performance Hotspots (profile-guided)**
- Profile before algorithmic tweaks (cProfile, perf, py-spy, Chrome Performance, database EXPLAIN).
- Quick wins: add caching (in-memory, Redis), lazy loading, batch I/O and DB queries, appropriate data structures, avoid N+1.
- Web/UI: bundle analysis, tree-shaking, code-splitting, critical rendering path.

**Security & Supply-Chain**
- Run dependency vulnerability scans (npm audit, safety, osv-scanner, Snyk).
- Enforce input sanitization, least-privilege, secret scanning (gitleaks, trufflehog) on existing flows.
- Review for OWASP Top 10 patterns in legacy endpoints and jobs.

**Test & Observability Debt**
- Ensure changed paths have meaningful tests; raise coverage on hot areas.
- Add structured logging, metrics, and tracing around optimized sections.
- Make CI fail on new lint or test regressions.

## Standard Workflow for Existing Repos
1. **Inventory & Baseline**: Clone/scan repo structure, languages, LOC, dependency graph, current test/lint status.
2. **Quick-Win Sweep**: Execute linters, dead-code detectors, dep auditors. Apply obvious fixes.
3. **Deep Analysis**: Profile critical user journeys, API endpoints, background jobs, or batch processes.
4. **Prioritize**: Score items by (impact × confidence) / effort. Create focused issues or a optimization backlog.
5. **Iterate Safely**: Implement → run full test suite + benchmarks → measure delta → document trade-offs.
6. **Harden & Monitor**: Update docs/architecture notes; add or improve observability; watch real-world metrics post-deploy.
7. **Repeat**: Re-baseline after significant changes; treat optimization as ongoing hygiene not one-off project.

## When to Extend Beyond Generic
Load language-specific references or dedicated skills for:
- Heavy algorithmic / data-intensive work
- Large-scale legacy migrations or monolith splits
- Domain-specific performance (e.g. ML inference, real-time systems)
- Framework idioms (React Server Components, Django ORM tuning, etc.)

Prefer lightweight built-in or stdlib solutions over new dependencies. Keep changes boring and reviewable.

This codex turns vague "make it better" requests into systematic, measurable improvements on real existing codebases.

