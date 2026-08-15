# KubeHunt Engineering Guidelines

## Project

KubeHunt is a CLI-based Kubernetes security posture scanner written in Go.

Its findings are mapped to OWASP Kubernetes Top 10:2025.

The scanner is intended to remain deterministic:
security findings must come from explicit rules and graph analysis,
not probabilistic LLM judgments.

## Engineering Principles

- Prefer simple, explicit Go code.
- Do not introduce abstractions without a concrete use case.
- Separate Kubernetes collection from security analysis.
- Security rules must never directly query Kubernetes.
- Rules operate against a normalized cluster state.
- Reporting must remain separate from detection.
- OWASP mappings belong to rule metadata.
- A finding may reference multiple OWASP categories.
- Never claim PASS when the scanner lacked the capability to assess a control.
- Represent unsupported assessment areas as PARTIAL or NOT_ASSESSED.
- Cluster operations must be read-only unless explicitly documented otherwise.

## Security

- Never log Secret values.
- Never persist kubeconfig credentials.
- Never silently request broader Kubernetes privileges.
- Do not add active exploitation functionality.
- Network reachability must not be claimed unless actually verified.
- A LoadBalancer or NodePort should be reported as potential exposure,
  not automatically as internet-accessible.
- Do not mark a namespace secure simply because a NetworkPolicy exists.
  Verify whether policies select the relevant workloads.

## Architecture

Use these layers:

CLI
Kubernetes Client
Collectors
Normalized ClusterState
Rule Engine
Graph Engine
Risk Engine
Reporter

Dependencies should generally flow downward through those layers.

## Tests

Every security rule must have:

- a positive test
- a negative test
- edge-case coverage where relevant

Use Kubernetes API objects directly in unit tests.

Tests must not require a real Kubernetes cluster unless they are integration tests.

Run before completing a task:

go test ./...
go vet ./...

## OWASP

Use OWASP Kubernetes Top 10:2025.

Current categories:

K01 Insecure Workload Configurations
K02 Overly Permissive Authorization Configurations
K03 Secrets Management Failures
K04 Lack of Cluster Level Policy Enforcement
K05 Missing Network Segmentation Controls
K06 Overly Exposed Kubernetes Components
K07 Misconfigured and Vulnerable Cluster Components
K08 Cluster to Cloud Lateral Movement
K09 Broken Authentication Mechanisms
K10 Inadequate Logging and Monitoring

Do not describe the project as "OWASP compliant."

Use terminology such as:

"Mapped to OWASP Kubernetes Top 10:2025."

## Scope Discipline

Do not implement unrelated features while completing a milestone.

Do not rewrite working modules without a demonstrated need.

When making an architectural change:
1. explain the reason
2. update documentation
3. update tests
4. then modify implementation
