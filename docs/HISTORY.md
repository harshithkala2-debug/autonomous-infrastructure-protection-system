# Project history and contributions

This document records how AIPS was developed and who did which part of the work.

> **How to read the tables:** the **left column (Author)** is design, direction and decisions. The **right
> column (Claude)** is implementation: code, tests, documentation and test runs, done on the author's
> instructions.

## Roles

| Contributor | Role |
|---|---|
| **The author**, [harshithkala2-debug](https://github.com/harshithkala2-debug), age 15 | Concept and system architecture, product direction, the decision on every feature and design trade-off, account and access management, and test direction. |
| **Claude**, an AI coding assistant by Anthropic, used through Claude Code | Implementation: the source code, automated tests, documentation, live test execution and the field test reports. It worked only from the author's instructions. |

Dates are in 2026. Version numbers match [CHANGELOG.md](../CHANGELOG.md).

---

## Design phase

The author wrote the system's concept document,
[`autonomous_infrastructure_protection_system_plan.md`](../autonomous_infrastructure_protection_system_plan.md),
before any code existed. It sets out the architecture that every later version builds on:

* a **three-level decision hierarchy**, modelled on a judicial system: detection, evaluation and final
  decision, with severe problems escalated straight to the top level;
* **specialised monitoring bots**, each responsible for one class of problem;
* **identity and access protection**, with limits per identity and a response when they are crossed;
* **adaptive repair**: record the known-good state, compare against it, correct, and verify until resolved;
* **two traffic-control valves** that reduce load on a component while it is repaired;
* a **three-layer backup architecture**: main layer, backup copy and protected vault;
* an **external intelligence fleet** that learns from publicly reported incidents and vulnerabilities;
* the end-to-end workflow, the target users and the open design questions.

## 22 November: foundation, adaptive behaviour and Google Cloud

| Author | Claude |
|---|---|
| Asked for the complete system to be built from the concept document as a **production-grade** implementation and published on GitHub. | Implemented **1.0.0** from the concept document: the decision hierarchy, the detector fleet, identity protection, repair, the traffic valves, the backup vault, the intelligence fleet, the authorisation policy, the audit ledger, a simulator with scenarios, the CLI, documentation and CI. Created the repository. |
| Completed the GitHub account steps. | Ran AIPS live, observe-only, on the author's workstation. Fixed the defect this found (**1.0.1**). |
| Specified three capabilities: **any layer can call any other**, **persistent experience** across runs, and **automatic exploration of repair strategies**. | Implemented the layer mesh, the experience store and the strategy selector (**1.1.0**). |
| Set the licensing policy for the early phase. | Applied the evaluation-only license (**1.1.1**). |
| Specified **Google Cloud** support, with the constraint that it cost nothing. | Implemented the Google Cloud integration, with no SDK and an API emulator for testing (**1.2.0**). |
| Set up the Google Cloud test projects and access. | Ran the live Google Cloud field test. A staged service-account misuse was disabled in Google IAM **31 seconds** after it happened, and 6 of 6 safety tests passed. Fixed the 3 defects the test found (**1.2.1**). |
| Directed a written report, thorough testing and closing the remaining gaps. | Implemented reversal of attacker-created resources, handling of late audit events, and human-account freezing (**1.3.0**), then verified them live. |

## 23 November: AI agent protection and open source

| Author | Claude |
|---|---|
| Specified **AI agent protection**: AIPS sits between an AI agent and the system and stops harmful or erratic actions, with the ability to **freeze, flag, fix and save**, following the AIPS model. Decided to release AIPS as **open source under the MIT License**. | Implemented the AgentGuard (**1.4.0**): harm rules, policy and behaviour analysis, prompt-injection detection, file checkpoints, revert, freeze, the Claude Code hook, the HTTP API and the demo. Relicensed under MIT. |
| Directed a full test run, an updated report, a clean repository and a working setup guide. Approved making the repository public. | Ran the live test with a real Claude Code agent: credential exfiltration was blocked and the agent frozen, a prompt injection was detected, and an overwritten file was restored. Wrote the setup guide and verified it on a fresh install. Published the field test report. |

## 24 November: the AIPS web, the sandbox and machine learning

| Author | Claude |
|---|---|
| Reviewed the remaining limitations. | Compiled them from the documentation. |
| Specified the next architecture: a **sandbox** as strong as the available hardware allows, inside a **closed domain** that outsiders can't enter, that must **never lock out the legitimate human** and must **stop agents from forging approvals or records**; **machine learning**; **multi-machine** operation; a **web of AIPS instances** with **protected storage** and an **orchestrator**; and a **hybrid sandbox connected to the cloud**. | Implemented **1.5.0**: the AIPS web (closed trust domain, hub and orchestrator, nodes, protected self-healing storage), human-only approvals that an agent can't forge, the hybrid sandbox (Windows low integrity with Job Object limits locally, remote sandbox nodes for risky work) and standard-library machine learning. |
| Made the four design decisions: a closed trust domain, integration into AIPS, a process-level sandbox for the available hardware, and no new ML dependencies. | Ran the live AIPS web test (a hub and real node processes, 12 attack scenarios): 12/12, reproducible over repeated runs. Fixed the defect it found. Updated the documentation and the field test report. |
| Requested this record of contributions and reviewed it before publication. | Wrote it from the commit history and the development record. |

---

## Summary

| Author | Claude |
|---|---|
| Concept and architecture (the concept document) | Source code (about 13,800 lines of Python) and automated tests (153) |
| Product direction for every release: the layer mesh, experience, strategy exploration, Google Cloud, AI agent protection, the AIPS web, the hybrid sandbox and machine learning | Turning each specification into a working, tested implementation |
| Design decisions and trade-offs | Simulator, benchmark and live test execution, with recorded evidence |
| Accounts, access, approvals and the decision to publish | Documentation and the field test reports |

All development by Claude was done on the author's instructions. Claude didn't set the project's direction.
