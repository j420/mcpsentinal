/**
 * K4 TP-03 — soft-delete pattern: the rule fires (Art.14 still applies)
 * but at reduced confidence via the soft_marker_reduces_severity factor.
 *
 * This fixture documents the charter's claim that SOFT markers do not
 * silence the finding — they only lower confidence.
 */

const users = {
  softDeleteUser(_id: string): void {
    // marks the record as deleted; recoverable until the trash bin is emptied
  },
};

export function onUserDeleted(id: string): void {
  users.softDeleteUser(id);
}
