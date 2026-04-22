/**
 * P3 — canonical cloud metadata endpoint registry.
 *
 * Each entry is a whole-token literal that reaches a cloud provider's
 * instance metadata service. Matching is case-insensitive for hostnames,
 * exact for IP literals.
 */

export type CloudProvider =
  | "aws"
  | "azure"
  | "gcp"
  | "alibaba"
  | "oracle"
  | "digitalocean";

export type EndpointFamily = "ipv4" | "ipv6" | "hostname";

export interface EndpointSpec {
  id: string;
  provider: CloudProvider;
  family: EndpointFamily;
  token: string;
  description: string;
  weight: number;
}

export const METADATA_ENDPOINTS: Record<string, EndpointSpec> = {
  "aws-ipv4": {
    id: "aws-ipv4",
    provider: "aws",
    family: "ipv4",
    token: "169.254.169.254",
    description:
      "AWS / Azure / GCP / DigitalOcean link-local IMDS endpoint. Any fetch to this " +
      "address from application code can retrieve IAM credentials, instance identity " +
      "tokens, and userdata containing secrets.",
    weight: 1.0,
  },
  "aws-ipv6": {
    id: "aws-ipv6",
    provider: "aws",
    family: "ipv6",
    token: "fd00:ec2::254",
    description: "AWS IPv6 IMDS endpoint (charter lethal edge #1).",
    weight: 1.0,
  },
  "gcp-hostname": {
    id: "gcp-hostname",
    provider: "gcp",
    family: "hostname",
    token: "metadata.google.internal",
    description:
      "GCP Compute Engine metadata server hostname — returns IAM service-account " +
      "tokens and project metadata.",
    weight: 1.0,
  },
  "azure-hostname": {
    id: "azure-hostname",
    provider: "azure",
    family: "hostname",
    token: "metadata.azure.com",
    description:
      "Azure Instance Metadata Service hostname — returns MSI / managed-identity tokens.",
    weight: 1.0,
  },
  "alibaba-ipv4": {
    id: "alibaba-ipv4",
    provider: "alibaba",
    family: "ipv4",
    token: "100.100.100.200",
    description:
      "Alibaba Cloud ECS metadata endpoint — returns RAM-role credentials.",
    weight: 1.0,
  },
  "oracle-hostname": {
    id: "oracle-hostname",
    provider: "oracle",
    family: "hostname",
    token: "metadata.oraclecloud.com",
    description: "Oracle Cloud Infrastructure metadata hostname.",
    weight: 0.95,
  },
};

/** Tokens that indicate a defensive / block context — exempt the finding. */
export const BLOCK_CONTEXT_TOKENS: Record<string, { description: string }> = {
  deny: { description: "deny-list / iptables DENY rule" },
  reject: { description: "iptables REJECT / nginx reject directive" },
  drop: { description: "iptables DROP rule / NetworkPolicy egress drop" },
  block: { description: "firewall block rule" },
  forbid: { description: "opa / gatekeeper forbid policy" },
};

/** IMDSv2 hop-limit inflation is a standalone config finding (lethal edge #5). */
export const HOP_LIMIT_TOKEN = "HttpPutResponseHopLimit";
