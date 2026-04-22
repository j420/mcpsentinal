---
rule_id: P3
interface_version: v2
severity: critical
owasp: MCP07-insecure-config
mitre: AML.T0054
risk_domain: container-runtime

threat_refs:
  - kind: spec
    id: AWS-IMDSv2-Specification
    url: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
    summary: >
      AWS Instance Metadata Service v2 (IMDSv2) was introduced
      specifically to defeat the "SSRF to 169.254.169.254" attack class
      by requiring a session token obtained via PUT with a short TTL.
      MCP servers that ingest untrusted URLs and then fetch them create
      an SSRF sink; a metadata-endpoint reference in the same codebase
      enables credential theft on any AWS, Azure, GCP, or Alibaba host.
      IMDSv1 is still the default on older AMIs and on most self-managed
      Kubernetes nodes.
  - kind: paper
    id: Capital-One-2019-Breach-Postmortem
    url: https://krebsonsecurity.com/2019/08/capital-one-data-theft-impacts-106m-people/
    summary: >
      The Capital One 2019 breach exfiltrated 106M customer records by
      chaining an SSRF in a WAF-exposed service into 169.254.169.254
      to steal the EC2 instance IAM credentials. Every P3 match is a
      miniature version of that precondition — if the containing MCP
      server has any SSRF-style sink (and most do), the chain is
      complete. Detection here is the earliest stop-gap.
  - kind: spec
    id: CVE-2019-5021-Class
    url: https://nvd.nist.gov/vuln/detail/CVE-2019-5021
    summary: >
      CVE-2019-5021 (Alpine Docker root with empty password) is
      cross-referenced because IMDS exposure on a privileged workload
      compounds the impact: credentials stolen via IMDS plus root
      inside the container produce a full cluster-wide credential
      harvesting primitive. The CVE itself is not required for
      exploitation, but it illustrates the container-runtime × IMDS
      attack-surface intersection.

lethal_edge_cases:
  - >
    IPv6 metadata endpoint — AWS exposes the same metadata service
    at fd00:ec2::254, Azure at fe80::a9fe:a9fe%eth0. A rule that only
    matches the IPv4 literal 169.254.169.254 false-negatives on IPv6
    configurations. The data table must include every IP family used
    by AWS, Azure, GCP, Alibaba, Oracle Cloud, and DigitalOcean.
  - >
    Hostname form — `metadata.google.internal`, `metadata.azure.com`,
    `100.100.100.200` (Alibaba) are equally valid entry points that
    resolve to the metadata service. The rule must match the hostname
    form in addition to the link-local IP. DNS resolution of these
    hostnames is node-level, so no DNS config is needed to reach them.
  - >
    URL-embedded form — a user-controlled URL variable that is later
    fetched represents a different detection surface: the SSRF. This
    rule specifically targets literal references to metadata endpoints
    in source or config. Dynamic SSRF is P4/C3 territory. A literal
    `https://169.254.169.254/latest/meta-data/iam/security-credentials/`
    in source is a positive — direct intent to fetch credentials.
  - >
    Block / deny rules — a declarative line like `deny 169.254.169.254`
    or `iptables -A OUTPUT -d 169.254.169.254 -j REJECT` REFERENCES the
    metadata endpoint but is the OPPOSITE posture. The rule must exempt
    lines that pair the endpoint with block / deny / reject / drop
    tokens.
  - >
    AWS IMDSv2 hop-limit — a config file setting HttpPutResponseHopLimit
    to 2 or higher exposes IMDSv2 to pod-level SSRF on EKS; hop limit 1
    is the safe default. A literal `HttpPutResponseHopLimit: 2` in a
    Terraform / CloudFormation file is a configuration finding in its
    own right. The rule flags the hop-limit inflation separately from
    the raw-endpoint reference.

edge_case_strategies:
  - ipv6-endpoint-enumeration
  - hostname-form-enumeration
  - block-rule-exemption
  - imdsv2-hop-limit-check
  - cloud-provider-coverage

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - endpoint_variant
    - provider
    - block_context_observed
  location_kinds:
    - source
    - config

obsolescence:
  retire_when: >
    AWS IMDSv1 is fully retired AND EKS / GKE / AKS ship by default
    with NetworkPolicy-blocked metadata egress for pod networks. At
    that point the finding becomes historical posture for legacy
    workloads still running without the new defaults.
---

# P3 — Cloud Metadata Service Access

**Author:** Senior MCP Infrastructure Security Engineer persona.
**Applies to:** TypeScript / JavaScript / Python source, docker-compose
YAML, Kubernetes manifests, Terraform / CloudFormation files, shell
launch scripts, and infrastructure-as-code configuration that
references a cloud metadata endpoint.

## What an auditor accepts as evidence

A NIST SP 800-190 / AWS IMDSv2 / Capital-One-postmortem auditor wants:

1. **Scope proof** — specific file + line + endpoint variant (IPv4 /
   IPv6 / hostname) + cloud provider. A `source`-kind Location lets
   the auditor navigate to the exact reference.

2. **Gap proof** — reference to a metadata endpoint in a fetch / request
   context (NOT paired with a block / deny / reject rule). The rule
   explicitly excludes defensive references that pair the endpoint with
   drop / deny primitives.

3. **Impact statement** — IAM credential theft → cross-service lateral
   movement, tied to the Capital One 2019 precedent.

## What the rule does NOT claim

- It does not claim the host is actually on AWS / Azure / GCP — the
  reference is suspicious regardless of the deployment target, because
  it indicates the codebase is designed to reach the metadata service
  when run in cloud.
- It does not verify whether IMDSv2 enforcement is configured at the
  instance level (the `http-tokens required` setting is usually in a
  different file). Missing IMDSv2 is a separate compliance finding.

## Why confidence is capped at 0.80

Metadata references are unambiguous in source; the uncertainty is
whether downstream IMDSv2 session-token requirements, NetworkPolicy
egress blocks, or pod-level IAM OIDC federation defeat exploitation.
0.80 preserves that room without suppressing the posture finding.
