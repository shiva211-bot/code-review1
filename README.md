# Static Analysis & Security Code Review Engine

A JavaScript static-analysis engine designed to identify security vulnerabilities, trace tainted data across function boundaries, analyze control flow, and report incomplete analysis explicitly rather than presenting uncertain results as definitive.

The project combines AST-based analysis, control-flow modeling, interprocedural taint tracking, threat-specific sanitizer models, and an empirical verification framework.

> **Project status:** Hardened static-analysis prototype. The engine includes regression tests, adversarial mutation testing, property-based checks, selected external benchmark cases, and explicit resource-limit safeguards. Passing these tests does not constitute a formal proof of soundness or guarantee detection accuracy on arbitrary programs.

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Security Analysis Capabilities](#security-analysis-capabilities)
- [Analysis Reliability](#analysis-reliability)
- [Verification and Testing](#verification-and-testing)
- [External Benchmark Methodology](#external-benchmark-methodology)
- [Technology Stack](#technology-stack)
- [Getting Started](#getting-started)
- [Running Verification](#running-verification)
- [Interpreting Results](#interpreting-results)
- [Current Limitations](#current-limitations)
- [Roadmap](#roadmap)
- [Repository](#repository)

## Overview

Traditional security scanners often rely on surface-level patterns that can miss vulnerabilities when data passes through multiple variables, functions, branches, or sanitization operations.

This project aims to address those limitations using structural and data-flow analysis.

The engine analyzes JavaScript source code to construct an abstract representation of program behavior, trace potentially untrusted values, evaluate security-sensitive operations, and identify unreachable code and analysis limitations.

Its core design goals are:

1. **Structural analysis:** Analyze parsed program syntax rather than relying exclusively on text matching.
2. **Interprocedural tracking:** Follow potentially unsafe data through function calls and return values.
3. **Flow sensitivity:** Account for assignments, reassignment, branching, and variable shadowing.
4. **Threat-specific sanitization:** Avoid treating a value as universally safe merely because it passes through a sanitizer.
5. **Explicit uncertainty:** Report when resource limits prevent analysis from completing.
6. **Reproducible verification:** Test expected security findings against selected regression cases and benchmark examples.

## Key Features

### 1. AST-Based JavaScript Analysis

The parser uses Acorn to process JavaScript into an ESTree-compatible Abstract Syntax Tree (AST).

The analysis pipeline uses source locations and structural information to examine statements, expressions, branches, loops, function definitions, and calls.

TypeScript-related preprocessing is limited to syntactic type erasure where supported; this project should not be interpreted as a complete TypeScript or TSX compiler frontend.

### 2. Control-Flow Graph Construction

The control-flow analysis models program execution through basic blocks and directed edges.

Supported structural elements include:

- Entry and exit blocks
- Statement blocks
- Conditional branches
- Loop headers and back-edges
- Branch joins
- Reachability analysis
- Detection of certain unreachable statements after terminating operations
- Cyclomatic complexity estimation

These structures provide context for reasoning about which execution paths can reach a security-sensitive operation.

### 3. Interprocedural Taint Analysis

The engine tracks potentially untrusted data beyond individual statements and functions.

Its analysis includes:

- Function parameter and return-value propagation
- Call-site argument mapping
- Multi-step variable assignments
- Object-property and destructured-property flows
- Recursive function analysis using iterative summaries
- Flow-sensitive environment updates
- Taint removal following safe reassignment
- Lexical scope handling and variable shadowing
- Branch joins that account for continuing and terminating paths

The purpose is to detect vulnerable data flows that may not be apparent from a single source line.

### 4. Threat-Specific Sanitizer Models

Sanitization is modeled according to the type of threat and the destination where a value is used.

Examples include:

- HTML escaping for relevant cross-site scripting contexts
- SQL parameterization for SQL injection prevention
- URL-component encoding for URL components
- Numeric conversion for selected query, command, and path contexts

A sanitizer that is appropriate for one context is not automatically considered safe in another. For example, HTML escaping does not, by itself, make string-concatenated SQL safe.

### 5. Recursive Fixed-Point Analysis

Recursive and mutually dependent function summaries can require repeated analysis.

The engine uses iterative summary evaluation and abstract-state comparisons to determine whether results have stabilized within configured resource bounds.

Where analysis cannot finish within those bounds, the engine is designed to expose an inconclusive status rather than silently treating incomplete results as fully analyzed.

### 6. Security and Reliability Dashboard

The verification interface presents selected analysis invariants, benchmark results, and regression outcomes.

Its purpose is to make testing evidence and analysis limitations visible, rather than implying that a passing test suite proves the analyzer correct for all programs.

## Architecture

The high-level analysis pipeline is:

```text
JavaScript Source
       |
       v
Parsing and AST Construction
       |
       v
Control-Flow and Function Modeling
       |
       v
Flow-Sensitive Taint Analysis
       |
       v
Interprocedural Summary Evaluation
       |
       v
Threat-Specific Source / Sink / Sanitizer Analysis
       |
       v
Findings, Metrics, and Incomplete-Analysis Status
       |
       v
Verification Dashboard
```

### Core analysis components

| Component                | Responsibility                                               |
| ------------------------ | ------------------------------------------------------------ |
| Parser and AST           | Parse source and retain structural information               |
| Control-flow analysis    | Model branches, loops, joins, and reachability               |
| Interprocedural analysis | Propagate abstract values across function calls              |
| Taint tracking           | Track potentially untrusted data and security-relevant flows |
| Sanitizer models         | Evaluate context-dependent safety transformations            |
| Verification engine      | Run invariant, regression, mutation, and benchmark tests     |
| Quality dashboard        | Present analysis status and empirical verification results   |

Implementation paths and module names may change as the architecture evolves.

## Security Analysis Capabilities

The current test corpus covers examples involving:

- SQL injection
- Cross-site scripting and HTML sanitization boundaries
- Command-injection-related flows
- Path-resolution-related flows
- URL destination versus URL component handling
- Prototype-pollution-related patterns
- Event-loop blocking through synchronous cryptographic operations
- Resource leaks involving timers and effects
- N+1 database query patterns
- Dead-code and control-flow reachability
- Safe reassignment and taint removal
- Recursive and multi-function data-flow propagation

These are areas represented in the project's selected test cases. Their inclusion does not imply exhaustive coverage of every variant of each vulnerability class.

## Analysis Reliability

### Explicit incomplete-analysis handling

Static analysis can encounter recursion, complex control flow, or other cases that exceed configured analysis budgets.

When the engine reaches a relevant resource limit, the expected behavior is to mark the result as incomplete or inconclusive and expose the associated status and warning.

A resource-limited result must not be interpreted as proof that the source is safe.

### Abstract-state joins

When control-flow paths merge, the analysis combines the information available on those paths. Constants should be retained only when the relevant values agree; conflicting values must not be arbitrarily treated as known constants.

### Scope and branch handling

The analysis includes regression checks for lexical shadowing, reassignment, branch-return isolation, and the distinction between paths that continue and paths that terminate.

These checks provide evidence about specific implementation behaviors, not a universal proof of soundness.

## Verification and Testing

The project includes multiple verification suites intended to detect regressions and evaluate selected analysis properties.

The following counts reflect the project's **reported verification results** and should be regenerated against the current commit before being presented as independently reproduced results.

| Suite                          |            Reported result | Scope                                                          |
| ------------------------------ | -------------------------: | -------------------------------------------------------------- |
| Soundness invariants           |                 8/8 passed | Selected abstract-analysis and incomplete-result invariants    |
| Interprocedural analysis       |     53/53 expectations met | Function propagation, recursion, sanitizers, and related flows |
| External benchmarks            | 20/20 classified correctly | 16 upstream-referenced examples and 4 local regressions        |
| Adversarial mutation testing   |         108/108 classified | Selected generated mutations and bypass variants               |
| Property-based testing         |        5/5 properties held | 124 reported test samples                                      |
| Ground-truth regression corpus |               16/16 passed | Selected expected findings and classifications                 |

### Reproducing verification

Run the full verification script from the repository root:

```bash
npx tsx scripts/verify-all.ts
```

The script invokes the following suites:

1. Soundness invariant checks
2. Interprocedural verification
3. External benchmark evaluation
4. Adversarial mutation and property-based testing
5. Ground-truth regression tests

Type-checking can be run separately:

```bash
npx tsc --noEmit
```

Build using the project's configured build script:

```bash
npm run build
```

**Verification requirement:** A successful-looking log is not sufficient on its own. The verification runner should assert expected suite outcomes and return a non-zero exit status when a required check fails. Confirm that behavior before relying on it in continuous integration.

## External Benchmark Methodology

The external benchmark suite contains 20 curated cases:

- 16 examples associated with upstream benchmark projects
- 4 locally authored regression cases

The referenced projects include OWASP Benchmark, Securibench-JS, and NodeGoat.

### Cross-language adaptations

OWASP Benchmark is Java-based. Cases adapted from it are translated into JavaScript/Express-style examples for evaluation by this JavaScript analyzer.

These adapted examples are not original JavaScript OWASP Benchmark files. Their classifications measure performance on the translated snippets and their stated ground-truth labels.

Securibench-JS and NodeGoat provide JavaScript-oriented reference material, although each selected case's provenance and adaptation should still be documented accurately.

### SHA-256 snippet fingerprints

The benchmark implementation computes a SHA-256 digest for the evaluated JavaScript snippet.

The reported `snippetSha256` field identifies the local snippet used for that evaluation. This supports repeatable identification of test content when the digest is independently recorded and checked.

A local snippet digest is distinct from the integrity of the original upstream artifact. Strong provenance records should separately retain:

- Upstream repository URL
- Full upstream commit SHA or immutable revision
- Upstream file path
- Upstream artifact digest
- Local evaluated snippet digest
- Original test identifier
- Ground-truth label and adaptation notes

**Important:** A digest computed during a run is not, by itself, proof that the source is authentic or unchanged from an earlier trusted version. Integrity verification requires comparison with a trusted, previously recorded digest.

### Understanding benchmark metrics

Precision, recall, specificity, accuracy, and F1 score summarize classifications within the evaluated dataset.

The reported 20/20 result means all 20 selected cases were classified as expected in that run. It does not establish a 100% detection rate on arbitrary applications, complete repositories, or unseen vulnerability patterns.

## Technology Stack

The repository currently declares dependencies and tooling that include:

- **Language:** TypeScript and JavaScript
- **AST parsing:** Acorn
- **AST traversal:** acorn-walk
- **UI:** React
- **Build tooling:** Vite
- **Execution and testing:** Node.js and tsx
- **Type checking:** TypeScript
- **Styling:** Tailwind CSS

Consult `package.json` for the current dependency versions and available scripts.

## Getting Started

### Prerequisites

Install a compatible version of Node.js and npm. A clean checkout and installed dependencies are recommended for reproducible results.

### Installation

Clone the repository:

```bash
git clone https://github.com/shiva211-bot/code-review1.git
cd code-review1
```

Install dependencies:

```bash
npm install
```

### Run the development server

```bash
npm run dev
```

Use the local URL printed by the development server to open the application.

### Type-check and build

```bash
npx tsc --noEmit
npm run build
```

### Run verification

```bash
npx tsx scripts/verify-all.ts
```

Run the checks against a clean working tree and record the commit SHA, runtime version, command output, and exit status when preparing a release or sharing verification claims.

## Interpreting Results

The engine's output should be understood in three categories:

- **Finding reported:** A configured analysis rule identified a potentially vulnerable pattern or data flow. Findings require contextual review and may still include false positives.
- **No finding reported:** The selected rules did not identify a vulnerability. This is not a guarantee that the code is safe.
- **Incomplete or inconclusive analysis:** The engine could not complete a relevant portion of the analysis within its configured bounds. This must not be interpreted as a clean result.

Security findings should be reviewed in the context of application architecture, framework behavior, runtime configuration, and deployment assumptions.

## Current Limitations

The project remains a prototype and has important limitations:

1. **No universal formal proof:** Selected invariant tests do not establish soundness for arbitrary programs.
2. **Finite benchmark coverage:** The curated benchmark set is small and cannot represent the full diversity of production applications.
3. **Cross-language adaptation:** Translated Java examples may not preserve every semantic detail of the original program.
4. **Framework and library modeling:** Analysis quality depends on accurate source, sink, sanitizer, and library behavior models.
5. **Resource-bounded recursion:** Some recursive analyses may remain inconclusive when the configured iteration budget is exhausted.
6. **Language coverage:** The Acorn-based frontend is not a full TypeScript/TSX compiler frontend.
7. **Runtime behavior:** Static analysis cannot automatically account for every dynamic runtime condition, external service response, or deployment configuration.
8. **Hash trust model:** Snippet fingerprints require trusted expected values and explicit comparisons to serve as integrity checks.

The absence of a reported finding should never be used as the sole basis for approving security-critical code.

## Roadmap

Potential next steps include:

- [ ] Add trusted, pinned SHA-256 checks for local and upstream benchmark artifacts.
- [ ] Verify upstream repository revisions and original test identifiers.
- [ ] Make the full verification runner fail on unexpected suite outcomes.
- [ ] Add continuous integration for type-checking, building, and verification.
- [ ] Expand benchmarks with independently validated ground truth.
- [ ] Add multi-file and framework-aware analysis cases.
- [ ] Test more complex control flow, recursion, aliasing, and sanitizer misuse.
- [ ] Track false-positive and false-negative regressions across releases.
- [ ] Document supported syntax, known gaps, and analysis budgets.
- [ ] Add security-focused peer review and independent evaluation.

## Repository

**GitHub:** [https://github.com/shiva211-bot/code-review1](https://github.com/shiva211-bot/code-review1)

Contributions should include focused regression tests, clear ground-truth explanations, reproducible commands, and documentation for any new source, sink, or sanitizer models.

## Disclaimer

This project is intended for research, development, and security-analysis experimentation. It is not a substitute for expert security review, dynamic testing, dependency auditing, or application-specific threat modeling.

Passing the project's verification suites demonstrates success on the tested cases and properties only. No guarantee is made that the engine detects every vulnerability or proves arbitrary programs secure.
