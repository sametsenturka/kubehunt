<div align="center">
  <img width="240" height="182" alt="KubeHunt logo" src="https://github.com/user-attachments/assets/77c72662-c71d-455e-97f9-1e3f940b681d" />
  <h1>KubeHunt</h1>
  <p>Deterministic, Kubernetes Security Posture Scanning from your terminal.</p>
  <p>Mapped to the <a href="https://owasp.org/www-project-kubernetes-top-ten/">OWASP Kubernetes Top 10:2025</a>.</p>
</div>

> [!IMPORTANT]
> KubeHunt is under active development. The current version provides cluster inventory, K01-K04 deterministic checks, and initial evidence-backed attack-path correlation. It does not yet provide JSON/SARIF output, CI severity gates, K05-K10 rules, or prebuilt release binaries.

## What KubeHunt does

KubeHunt connects to the Kubernetes cluster selected by your kubeconfig, builds a normalized in-memory view of the cluster, evaluates explicit security rules, constructs a typed relationship graph, and prints an inventory plus findings.

The scanner is deliberately deterministic: findings come from Kubernetes objects, documented Kubernetes semantics, and explicit graph relationships. An LLM is not used to decide whether a resource is vulnerable.

Current capabilities include:

- Cluster inventory across 16 Kubernetes resource types.
- OWASP K01:2025 workload configuration checks.
- OWASP K02:2025 effective RBAC analysis across subjects, bindings, roles, and permissions.
- OWASP K03:2025 Secret environment-reference checks without reading Secret values.
- OWASP K04:2025 Pod Security Admission, ValidatingAdmissionPolicy, and validating webhook checks.
- Analysis of regular and init containers, plus ephemeral containers for K03 Secret environment references.
- Deduplication of supported controller templates and their child Pods.
- An in-memory attack graph with stable node identifiers and evidence-bearing semantic edges.
- High-confidence correlation for Pod creation and RBAC modification opportunities.
- Human-readable terminal findings with evidence and remediation.
- Namespace and kubeconfig-context selection.
- Client-side enforcement of read-only Kubernetes API access.

## Installation

### Requirements

- [Go 1.25 or newer](https://go.dev/doc/install)
- Access to a Kubernetes cluster
- A trusted [kubeconfig](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/) containing the target context
- Kubernetes credentials with the read permissions listed in [Required Kubernetes permissions](#required-kubernetes-permissions)

`kubectl` is useful for checking contexts and permissions, but KubeHunt itself connects with `client-go` and does not shell out to `kubectl`.

### Install with Go

```bash
go install github.com/sametsenturka/kubehunt/cmd/kubehunt@latest
kubehunt version
```

Go installs the executable under `$(go env GOPATH)/bin`. Add that directory to your `PATH` if `kubehunt` is not found.

For the current PowerShell session on Windows:

```powershell
$env:Path += ";$(go env GOPATH)\bin"
kubehunt version
```

### Build from source

Linux and macOS:

```bash
git clone https://github.com/sametsenturka/kubehunt.git
cd kubehunt
go build -trimpath -o ./kubehunt ./cmd/kubehunt
./kubehunt version
```

Windows PowerShell:

```powershell
git clone https://github.com/sametsenturka/kubehunt.git
Set-Location kubehunt
go build -trimpath -o .\kubehunt.exe .\cmd\kubehunt
.\kubehunt.exe version
```

There is not yet a versioned GitHub Release with downloadable binaries. Source installation is currently the supported installation path, and locally built binaries report a development version.

## Quick start

Check the context that Kubernetes tools currently use:

```bash
kubectl config current-context
kubectl config get-contexts
```

Scan every namespace in the current context:

```bash
kubehunt scan cluster
```

Scan a specific context:

```bash
kubehunt scan cluster --context docker-desktop
```

Scan one or more namespaces:

```bash
kubehunt scan cluster --namespace production
kubehunt scan cluster -n production -n payments
kubehunt scan cluster -n production,payments
```

Use a specific kubeconfig file:

```bash
kubehunt scan cluster --kubeconfig /path/to/kubeconfig --context my-context
```

PowerShell example:

```powershell
kubehunt scan cluster --kubeconfig "$HOME\.kube\config" --context docker-desktop
```

### Example output

```text
Cluster: docker-desktop
Context: docker-desktop
Server: kubernetes.docker.internal
Namespace scope: all namespaces

Namespaces           6
Pods                 20
Deployments          10
StatefulSets         0
DaemonSets           1
Services             12
Ingresses            0
ServiceAccounts      46
Roles                12
ClusterRoles         68
RoleBindings         12
ClusterRoleBindings  55
NetworkPolicies      0
ValidatingAdmissionPolicies        0
ValidatingAdmissionPolicyBindings  0
ValidatingWebhookConfigurations    2

Findings: 1

HIGH KSCAN-K01-001
OWASP K01:2025 - Insecure Workload Configurations

Resource:
Deployment/payment-api

Namespace:
production

Evidence:
container "api": securityContext.privileged=true

Description:
A container is explicitly configured to run in privileged mode.

Remediation:
Set securityContext.privileged to false and grant only the narrowly required permissions.
```

Actual counts and findings depend on the selected cluster and the permissions of the kubeconfig identity.

## CLI reference

```text
kubehunt scan cluster [flags]
kubehunt version
```

`scan cluster` flags:

| Flag | Short | Description |
| --- | --- | --- |
| `--context <name>` | | Use the named kubeconfig context. Defaults to the current context. |
| `--kubeconfig <path>` | | Use an explicit kubeconfig file. |
| `--namespace <name>` | `-n` | Limit namespaced resources to one or more namespaces. Repeat or comma-separate the flag. |
| `--allow-exec-credential` | | Permit trusted kubeconfig exec/auth-provider credentials. Disabled by default. |
| `--help` | `-h` | Show command help. |

Namespace filtering applies to namespaced resources. Cluster-scoped resources such as ClusterRoles and ClusterRoleBindings are still collected because effective RBAC analysis depends on them.

### Managed-cluster credentials

Some kubeconfigs for EKS, GKE, AKS, and other managed clusters execute a local credential helper. Because a kubeconfig can execute code, KubeHunt rejects exec and legacy auth-provider credentials by default.

Use the opt-in only after inspecting and trusting the kubeconfig and its configured executable:

```bash
kubehunt scan cluster --context my-managed-cluster --allow-exec-credential
```

## Collected resources

KubeHunt currently collects and normalizes:

| Scope | Resources |
| --- | --- |
| Cluster-scoped | Namespaces, ClusterRoles, ClusterRoleBindings, ValidatingAdmissionPolicies, ValidatingAdmissionPolicyBindings, ValidatingWebhookConfigurations |
| Namespaced | Pods, Deployments, StatefulSets, DaemonSets, Services, Ingresses, ServiceAccounts, Roles, RoleBindings, NetworkPolicies |

Secret objects and Secret values are not collected. The normalized model can contain Secret *references* exposed by container environment configuration, workload volumes, or ServiceAccount metadata, but not Secret payloads or inline environment values.

## Security checks

### OWASP K01:2025 — Insecure Workload Configurations

K01 rules inspect Pods and the Pod templates of Deployments, StatefulSets, and DaemonSets. Both regular containers and init containers are evaluated.

| Rule | Detection | Default severity |
| --- | --- | --- |
| `KSCAN-K01-001` | Privileged container | High |
| `KSCAN-K01-002` | Container explicitly running as UID 0 | High |
| `KSCAN-K01-003` | Privilege escalation enabled or unset where Kubernetes defaults it to enabled | High |
| `KSCAN-K01-004` | Explicitly added dangerous Linux capabilities | High |
| `KSCAN-K01-005` | Host PID namespace enabled | High |
| `KSCAN-K01-006` | Host IPC namespace enabled | High |
| `KSCAN-K01-007` | Host network namespace enabled | High |
| `KSCAN-K01-008` | Sensitive hostPath mounted by a container | High |
| `KSCAN-K01-009` | Seccomp explicitly set to `Unconfined` | Medium |
| `KSCAN-K01-010` | Writable root filesystem, including the Kubernetes default when unset | Medium |

KubeHunt does not treat every missing field as insecure. A missing value is reported only where Kubernetes runtime/default semantics justify the conclusion. For example, an unset `privileged` field is not reported as privileged, while an unset `readOnlyRootFilesystem` field results in a writable root filesystem.

### OWASP K02:2025 — Overly Permissive Authorization Configurations

K02 analysis resolves effective native Kubernetes RBAC relationships:

```text
Subject -> RoleBinding/ClusterRoleBinding -> Role/ClusterRole -> Permission
```

It preserves namespace scope, resolves ClusterRole aggregation, accounts for subject type and privilege-escalation potential, and adjusts severity instead of treating every broad permission as Critical.

| Rule | Detection |
| --- | --- |
| `KSCAN-K02-001` | Effective cluster-admin binding |
| `KSCAN-K02-002` | Broad wildcard verb, resource, or API group permission |
| `KSCAN-K02-003` | Secret `get`, `list`, `watch`, or wildcard access |
| `KSCAN-K02-004` | Pod exec permission |
| `KSCAN-K02-005` | Pod attach permission |
| `KSCAN-K02-006` | Pod creation permission |
| `KSCAN-K02-007` | ServiceAccount token creation permission |
| `KSCAN-K02-008` | RBAC `bind` permission |
| `KSCAN-K02-009` | RBAC `escalate` permission |
| `KSCAN-K02-010` | Identity impersonation permission |
| `KSCAN-K02-011` | Role, ClusterRole, RoleBinding, or ClusterRoleBinding modification |

K02 covers native RBAC objects visible to the scanner. It cannot determine external identity-provider group membership, webhook/ABAC authorization, cloud IAM mappings, business necessity, or time-bound access.

`KSCAN-K02-003` is primarily mapped to K02 because authorization is the defect and also related to K03 because the grant can expose Secret contents.

### OWASP K03:2025 — Secrets Management Failures

K03 checks use only references in Pod and workload configuration. KubeHunt never requests the referenced Secret object and never stores or reports its value.

| Rule | Detection | Default severity |
| --- | --- | --- |
| `KSCAN-K03-001` | A regular, init, or ephemeral container injects one Secret key through an environment variable | Medium |
| `KSCAN-K03-002` | A regular, init, or ephemeral container injects every key from a Secret through `envFrom.secretRef` | High |

These findings identify credential exposure through process environment state, where debug output or application logging can disclose values. They do not claim that a value has been logged, read, or compromised. Mounted Secret files are not reported by these rules because file-based delivery is the preferred Kubernetes alternative when configured carefully.

K03 cannot currently assess Secret contents, image layers, source repositories, application logs, etcd encryption, rotation history, external secret stores, or long-lived Secret metadata.

### OWASP K04:2025 — Lack Of Cluster Level Policy Enforcement

K04 reports explicit non-enforcing or fail-open admission configuration:

| Rule | Detection | Default severity |
| --- | --- | --- |
| `KSCAN-K04-001` | Namespace explicitly sets `pod-security.kubernetes.io/enforce=privileged` | Medium |
| `KSCAN-K04-002` | ValidatingAdmissionPolicyBinding uses Audit/Warn without `Deny` | Medium |
| `KSCAN-K04-003` | ValidatingAdmissionPolicy explicitly sets `failurePolicy=Ignore` | Medium |
| `KSCAN-K04-004` | Validating admission webhook explicitly sets `failurePolicy=Ignore` | Medium |

An absent Pod Security Admission label is not automatically a finding because the API server may define cluster-wide defaults that are not visible through ordinary resource collection. Likewise, the absence of a VAP or webhook does not prove that no policy engine exists. K04 results therefore remain partial and do not claim complete policy coverage.

## Attack-path correlation

KubeHunt builds an in-memory directed graph from observed Kubernetes resources. Nodes use stable identifiers; edges have semantic types, confidence, scope, and supporting evidence. No external graph database is required.

| Correlation | Status | Meaning |
| --- | --- | --- |
| `KSCAN-PATH-001` | Model implemented; currently dormant | Potential exposure -> privileged workload -> ServiceAccount -> excessive RBAC -> Secret read. It requires a supporting K06 exposure finding, and K06 rules are not implemented yet. |
| `KSCAN-PATH-002` | Active | Workload -> ServiceAccount -> effective, unconstrained Pod creation permission -> privileged workload creation opportunity. |
| `KSCAN-PATH-003` | Active | ServiceAccount -> effective RoleBinding/ClusterRoleBinding update or patch permission -> privilege-escalation opportunity. |

Correlations are configuration-based attack-path hypotheses, not proof of exploitation. KubeHunt emits a path only when every required graph edge is confirmed and carries evidence. It does not claim that admission policy would accept a malicious workload, that an endpoint is reachable from the Internet, or that a permission has been exercised.

## Required Kubernetes permissions

KubeHunt only needs `get` and `list` access to its current inventory. It does not need Secret access, write verbs, impersonation, exec, attach, proxy, port-forward, or ServiceAccount token creation.

An administrator can use a role similar to the following and bind it to the user, group, or ServiceAccount represented by the scanner's kubeconfig:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kubehunt-reader
rules:
  - apiGroups: [""]
    resources:
      - namespaces
      - pods
      - services
      - serviceaccounts
    verbs: ["get", "list"]
  - apiGroups: ["apps"]
    resources:
      - deployments
      - statefulsets
      - daemonsets
    verbs: ["get", "list"]
  - apiGroups: ["networking.k8s.io"]
    resources:
      - ingresses
      - networkpolicies
    verbs: ["get", "list"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources:
      - roles
      - clusterroles
      - rolebindings
      - clusterrolebindings
    verbs: ["get", "list"]
  - apiGroups: ["admissionregistration.k8s.io"]
    resources:
      - validatingadmissionpolicies
      - validatingadmissionpolicybindings
      - validatingwebhookconfigurations
    verbs: ["get", "list"]
```

Example binding template for an existing user:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubehunt-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kubehunt-reader
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: REPLACE_WITH_KUBECONFIG_USERNAME
```

Creating RBAC objects changes the cluster and requires administrator approval. Review the manifests, replace the subject, and follow your organization's access process. The scanner itself never creates these objects or requests broader permissions.

Check access before scanning:

```bash
kubectl auth can-i list pods --all-namespaces
kubectl auth can-i list clusterroles
kubectl auth can-i list clusterrolebindings
kubectl auth can-i list validatingadmissionpolicies.admissionregistration.k8s.io
kubectl auth can-i list validatingwebhookconfigurations.admissionregistration.k8s.io
```

The current scanner returns an incomplete-inventory error if a required collection is forbidden or unavailable; it does not silently interpret a denied list as an empty, secure result.

## Security model

- **Read-only API guard:** the Kubernetes transport accepts only HTTP `GET` and `HEAD`.
- **Dangerous subresource blocking:** Pod exec/attach/proxy/port-forward, node/service proxy, and ServiceAccount token subresources are rejected even when accessed with a read-shaped request.
- **TLS required:** cluster API URLs must use HTTPS, and kubeconfigs using `insecure-skip-tls-verify` are rejected.
- **No credential persistence:** KubeHunt uses client-go's kubeconfig loading and does not write credentials.
- **No Secret collection:** Secret objects and values do not enter the current inventory.
- **No active exploitation:** KubeHunt reads configuration; it does not execute commands in workloads, probe services, mint tokens, or mutate resources.
- **No probabilistic adjudication:** rules and correlations are deterministic. A future optional AI layer may explain an existing finding, but it must not decide findings, severity, or exit status.
- **Safe kubeconfig default:** local credential plugins require an explicit trust opt-in.

Kubernetes resource names, labels, annotations, user names, group names, and server hostnames can still be sensitive. Review and redact terminal output before sharing it publicly.

## Architecture

```text
CLI
  -> kubeconfig + guarded client-go client
  -> Kubernetes collectors
  -> normalized ClusterState
  -> deterministic K01-K04 rule engine
  -> in-memory relationship graph
  -> deterministic attack-path correlator
  -> terminal reporter
```

The main boundaries are kept separate:

- Collectors perform Kubernetes I/O and normalization.
- Rules operate only on normalized cluster state.
- The RBAC model calculates reusable effective permissions.
- The graph models resource and identity relationships.
- Correlation emits ordinary findings supported by graph evidence.
- Reporting formats already-computed results and never queries the cluster.

## OWASP coverage and project status

KubeHunt is mapped to OWASP Kubernetes Top 10:2025; it is not “OWASP compliant,” certified, or endorsed by OWASP.

| Category | Current status |
| --- | --- |
| K01 Insecure Workload Configurations | Implemented for Pods, Deployments, StatefulSets, and DaemonSets; regular and init containers only. |
| K02 Overly Permissive Authorization Configurations | Implemented for visible native Kubernetes RBAC; external authorizers and identity membership remain out of scope. |
| K03 Secrets Management Failures | Partially implemented for Secret-to-environment references and related native RBAC exposure; Secret values, storage, rotation, repositories, images, and logs are not assessed. |
| K04 Lack of Cluster Level Policy Enforcement | Partially implemented for explicit PSA privileged enforcement, non-denying VAP bindings, and fail-open VAP/webhook settings; cluster defaults and policy-engine CRDs are not assessed. |
| K05 Missing Network Segmentation Controls | Not assessed. NetworkPolicies are collected and represented in the graph only. |
| K06 Overly Exposed Kubernetes Components | Not assessed. Services and Ingresses are collected, but Internet reachability is not inferred. |
| K07 Misconfigured and Vulnerable Cluster Components | Not assessed. |
| K08 Cluster to Cloud Lateral Movement | Not assessed. |
| K09 Broken Authentication Mechanisms | Not assessed. |
| K10 Inadequate Logging and Monitoring | Not assessed. |

The CLI does not yet emit a formal category coverage report. Until that capability exists, the absence of findings in an unimplemented category must not be interpreted as a pass.

### Current limitations

- Terminal output is the only report format; JSON and SARIF are planned.
- `--fail-on` and CI-specific exit policy are not implemented. A successful scan exits successfully even when findings exist; collection or analysis errors return a non-zero exit code.
- Contextual risk scoring is not implemented.
- Secret metadata collection is not implemented, and Secret values are intentionally excluded.
- K03 does not scan literal environment values because retaining or reporting possible credentials would violate the default data-minimization boundary.
- K04 cannot prove complete cluster-wide policy coverage from Namespace labels and native admission objects alone.
- Jobs, CronJobs, and ReplicaSets are not implemented as first-class desired-state targets; K01-specific ephemeral-container checks are also not implemented.
- Admission policy, runtime behavior, cloud networking, CNI enforcement, control-plane configuration, node configuration, audit pipelines, and verified Internet reachability are not visible.
- Collection failures currently stop the scan with an incomplete-inventory error rather than producing a machine-readable partial-coverage report.
- A tested Kubernetes version compatibility matrix has not yet been published.
- Prebuilt, checksummed release artifacts and version stamping are not yet available.

## Testing with a local cluster

[kind](https://kind.sigs.k8s.io/docs/user/quick-start/) is a convenient way to create an isolated local Kubernetes cluster:

```bash
kind create cluster --name kubehunt-lab
kubehunt scan cluster --context kind-kubehunt-lab
```

For security-rule testing, [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat) provides intentionally vulnerable Kubernetes workloads and supports kind-based labs. Run vulnerable environments only on an isolated local system; do not expose them to untrusted networks or deploy them in production.

Kubernetes Goat is a separate project. Its scenarios do not guarantee coverage of every KubeHunt rule, so purpose-built test manifests may still be needed for individual positive and negative cases.

## Troubleshooting

### `context does not exist`

The value passed to `--context` must be a kubeconfig context name, not a Docker container name or arbitrary cluster label.

```bash
kubectl config get-contexts
kubehunt scan cluster --context <EXACT_CONTEXT_NAME>
```

For example, Docker Desktop commonly uses `docker-desktop`, while a kind cluster named `kubehunt-lab` commonly uses `kind-kubehunt-lab`.

### `exec and auth-provider credentials are disabled by default`

Inspect the kubeconfig and its credential command. If you trust both, repeat the scan with `--allow-exec-credential`.

### `insecure-skip-tls-verify is not allowed`

Configure the kubeconfig with the cluster's trusted certificate authority. KubeHunt intentionally has no flag to bypass TLS verification.

### `cluster inventory is incomplete: ... forbidden`

The kubeconfig identity is missing `get` or `list` access for at least one collected resource. Compare its access with [Required Kubernetes permissions](#required-kubernetes-permissions). KubeHunt will not request or create additional privileges automatically.

### `kubehunt: command not found`

Add the Go binary directory reported by `go env GOPATH` to your `PATH`, or run the locally built executable using its full path.

## Development

Clone the repository and run the required checks:

```bash
git clone https://github.com/sametsenturka/kubehunt.git
cd kubehunt
go test ./...
go vet ./...
go build ./cmd/kubehunt
```

Format changed Go files with `gofmt` before committing. Unit tests use Kubernetes API objects and fake clients; they do not require a live cluster.

Contributions should preserve these project rules:

- Keep collection, detection, graph analysis, risk, and reporting separate.
- Add positive, negative, and relevant edge-case tests for every security rule.
- Never read or log Secret values.
- Never add active exploitation behavior.
- Never describe inferred exposure or an attack path as proven exploitability.
- Keep OWASP mappings in rule metadata.
- Keep findings deterministic and evidence-backed.

Open bugs and feature proposals in [GitHub Issues](https://github.com/sametsenturka/kubehunt/issues). Never attach kubeconfigs, credentials, tokens, Secret values, or unredacted sensitive cluster output to a public issue.

## Roadmap

Near-term work includes:

- Formal capability and OWASP coverage reporting, including explicit `PARTIAL` and `NOT_ASSESSED` states.
- JSON and SARIF 2.1.0 reporters.
- CI severity thresholds with `--fail-on`.
- Transparent contextual risk scoring.
- K05-K06 deterministic rules and activation of the exposure-to-Secret attack path.
- Safe Secret metadata collection without Secret payloads.
- Versioned, checksummed cross-platform GitHub Releases.
- A Kubernetes compatibility matrix and integration-test environments.
- An optional, non-authoritative AI explanation boundary after deterministic analysis.

## License

A project-level license has not yet been added. Until a license is published, do not assume that the public repository grants permission to use, modify, or redistribute the software. This should be resolved before the first public release.

## Disclaimer

KubeHunt reports configuration risks visible through the Kubernetes API at scan time. It is not a penetration test, proof of compromise, complete authorization audit, runtime monitor, or guarantee of cluster security. Always review findings in the context of admission controls, workload behavior, identity systems, networking, and organizational policy.

OWASP and the OWASP Kubernetes Top 10 are trademarks and projects of the OWASP Foundation. KubeHunt is an independent project and is not affiliated with or endorsed by OWASP.
