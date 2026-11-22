# Autonomous Infrastructure Protection System

## Working Concept Plan

**Status:** Early-stage architecture concept\
**Purpose:** Record the system discussed so far without claiming that it
is novel, proven, or already implemented.

------------------------------------------------------------------------

## 1. Overall concept

Build an independently operating system made up of specialised software
bots/agents that help protect and maintain an organisation's technology
infrastructure.

The system is intended to combine:

-   Continuous infrastructure monitoring
-   Detection and investigation of weaknesses, anomalies, and failures
-   Hierarchical evaluation and decision-making
-   Identity and access protection
-   Automated correction and repair
-   Traffic/load control during problems
-   Backup and recovery protection
-   Intelligence gathered from publicly reported incidents and
    vulnerabilities

The intended outcome is a coordinated system that can identify problems,
assess their significance, take an appropriate response, and verify the
result.

## 2. Three-level monitoring and decision architecture

The central monitoring fleet is organised into three levels, compared
conceptually to a judicial hierarchy.

### Level 1 --- Initial detection

-   A fleet of monitoring and data-collection bots observes
    infrastructure activity.
-   Bots look for weaknesses, anomalies, unusual changes, and possible
    failures.
-   Findings are flagged and reported to Level 2.
-   Small issues can be identified early, before they grow into larger
    incidents.

### Level 2 --- Further evaluation

-   Evaluates reports received from Level 1.
-   Examines evidence in greater depth.
-   Helps distinguish genuine problems from false alarms.
-   Determines whether an issue should be handled at this level or
    escalated.

### Level 3 --- Final decision-making

-   Handles issues requiring the highest level of evaluation and
    decision-making.
-   Determines the appropriate response to serious incidents.
-   Coordinates the relevant corrective action.

### Escalation paths

Not every issue must pass through all three levels.

-   Ordinary findings can move from Level 1 to Level 2 and then Level 3
    as needed.
-   Serious or urgent issues can bypass an intermediate level.
-   A Level 1 finding may go directly to Level 3 when its severity
    warrants immediate escalation.
-   The architecture is intended to avoid unnecessary delay when an
    incident is already serious.

## 3. Specialised bots and repair responsibilities

The system is intended to use specialised bots rather than relying on
one general-purpose agent for every task.

Different bots may collect data, evaluate findings, investigate specific
areas, or carry out repairs. Each level has access to the information
needed for its role.

The broader design includes repair capability at the relevant levels, so
that identified problems can be addressed rather than merely reported.

The exact division of repair permissions, approval rules, and
coordination between repair bots remains to be specified in the detailed
design.

## 4. Identity and access protection

A separate fleet of bots monitors identities, accounts, applications,
services, and their access permissions.

The intended approach is:

-   Give each identity only the access it is supposed to have.
-   Define an appropriate permission boundary for each identity.
-   Detect requests or behaviour that exceed or depart from that
    boundary.
-   Send suspicious activity for further evaluation.
-   Use behavioural patterns and available evidence to distinguish
    legitimate activity from possible malicious activity.
-   Freeze access when the evaluation indicates that this is warranted.
-   Provide a way for a legitimate user or administrator to report an
    incorrect restriction and have it reviewed.

The purpose is to prevent unnecessary access and detect suspicious
permission use without treating every unusual action as malicious.

## 5. Adaptive operation and automatic repair

The proposed acting/repair system keeps a record of the initial
infrastructure design and its known working state.

When a malfunction occurs, the system is intended to:

1.  Identify the affected component or process.
2.  Compare its current state and behaviour with the recorded working
    state.
3.  Identify the change or condition associated with the malfunction.
4.  Determine a suitable correction.
5.  Apply the correction through the relevant repair mechanism.
6.  Continue checking the system until the main issue is resolved.

The concept also includes two traffic-control valves intended to slow or
limit the data stream when necessary, reducing load on an affected part
of the infrastructure while the issue is being handled.

The exact valve behaviour, thresholds, and relationship to the repair
process will need to be documented in the implementation specification.

## 6. Backup and recovery architecture

The backup concept uses separate layers, with an analogy to making a
duplicate of a written document and storing it somewhere separate from
the original.

### Main layer

-   Contains the organisation's working data.

### Backup-copying layer

-   Copies data from the main layer.
-   The intention is to preserve the data in detail, rather than relying
    only on a high-level summary.

### Protected vault layer

-   Stores a separate copy in a more restricted location.
-   The proposed access model includes restricting access to the
    organisation's known IP address.
-   The IP information is intended to remain private to the
    organisation.

The objective is to keep backup data separate from the main working
environment so that a problem affecting the main environment does not
automatically destroy the backup.

## 7. External intelligence fleet

In addition to monitoring a customer's own infrastructure, the proposed
system includes bots that gather information from public sources.

Potential sources include:

-   Public vulnerability disclosures
-   Security advisories
-   Company incident reports and outage postmortems
-   Engineering and reliability blogs
-   Public technical research

The intended workflow is:

1.  Collect reports about failures or vulnerabilities affecting other
    organisations.
2.  Extract the technical cause or failure pattern.
3.  Evaluate whether that pattern could apply to a customer's
    infrastructure.
4.  Check the customer's environment for relevant exposure or similar
    conditions.
5.  Send supported findings into the system's evaluation hierarchy.
6.  Recommend or carry out an appropriate preventive measure, depending
    on the system's authorised capabilities.

A public report is a source of intelligence, not proof that a customer's
environment has the same weakness. The system must establish relevance
before treating it as an actionable finding.

## 8. Intended end-to-end workflow

A possible end-to-end sequence is:

1.  Monitoring bots collect infrastructure data.
2.  A bot detects an anomaly, weakness, or unusual change.
3.  The finding is sent through the appropriate evaluation level.
4.  Serious issues can be escalated directly to a higher level.
5.  Relevant specialised bots investigate the issue.
6.  The decision-making level selects an appropriate response.
7.  The relevant repair, access-control, traffic-control, or recovery
    capability acts.
8.  Monitoring continues to establish whether the issue has been
    resolved.
9.  Findings and outcomes can inform future evaluation.

External intelligence can enter this workflow when a public incident
suggests a risk worth checking in the customer's environment.

## 9. Intended users and potential customers

Organisations that operate complex infrastructure may have a need for
coordinated monitoring, security, reliability, and recovery
capabilities.

Potential customer categories discussed include:

-   Large cloud and technology companies
-   Large SaaS providers
-   Banks and other financial institutions
-   Telecommunications companies
-   Managed service providers

Companies discussed as potential organisations to approach or benchmark
against include:

-   Google
-   Microsoft
-   Amazon / AWS
-   Cloudflare

These are potential audiences and comparison targets, not confirmed
customers or endorsers.

## 10. Delivery and evaluation goal

The intended submission to a technology company is the working
technology itself, not only a research paper or an idea description.

The intended package would include:

-   The functioning system
-   Its architecture and technical documentation
-   Demonstrations of its operation
-   Test methods and results
-   Reproducible evidence of its performance
-   Comparisons with relevant existing tools, where appropriate

The goal is to let engineers independently inspect and evaluate the
implementation and its results.

Any testing of another organisation's systems must take place only in an
authorised environment. The system should first be demonstrated in
infrastructure that the developer owns or has explicit permission to
test.

## 11. Current scope and open design details

This document records the concept described so far. It is not a claim
that the system has been implemented, validated, or shown to outperform
existing products.

The following details still need to be written into a complete technical
specification:

-   Exact bot roles and responsibilities
-   How bots exchange data and coordinate
-   What evidence each evaluation level receives
-   Escalation criteria and severity definitions
-   Which actions each bot is authorised to perform
-   How repair actions are checked
-   How the system handles conflicting findings
-   How the system records its decisions and changes
-   How the two traffic-control valves operate
-   Backup frequency, retention, isolation, and restoration process
-   How external reports are checked for relevance and accuracy
-   Deployment, scaling, and integration requirements
-   Test scenarios, benchmarks, and success criteria

These are specification topics to detail; their presence here does not
imply that the underlying design has been omitted or that the system
necessarily lacks a solution.

------------------------------------------------------------------------

**Working description:** A coordinated, multi-agent infrastructure
protection system combining hierarchical monitoring and evaluation,
identity and access protection, automated repair, adaptive traffic
control, layered backup and recovery, and external incident
intelligence.
