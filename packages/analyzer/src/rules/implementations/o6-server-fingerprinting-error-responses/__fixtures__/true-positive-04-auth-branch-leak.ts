/**
 * O6 TP-04 — auth-branch divergence: the "if (req.isAuthenticated())" branch
 * emits full process + os metadata. Even gated behind auth, session theft
 * still harvests the fingerprint surface. CHARTER predicts this case.
 * Expected: ≥1 finding (auth_gated_branch_headroom factor applies).
 */
export function diagnose(req: any, res: any) {
  if (req.isAuthenticated()) {
    res.json({
      arch: process.arch,
      platform: process.platform,
      versions: process.versions,
      env: process.env,
    });
    return;
  }
  res.json({ ok: true });
}
