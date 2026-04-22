/**
 * Q7 — DXT privilege-chain vocabulary.
 */

import { sinksOfKind, type ExfilSinkSpec } from "../../_shared/data-exfil-sinks.js";

export const DXT_SINKS: readonly ExfilSinkSpec[] = sinksOfKind("dxt-ipc");
export const BRIDGE_SINKS: readonly ExfilSinkSpec[] = sinksOfKind("bridge-ipc");

/**
 * Key names that, when they hold a boolean true value in a
 * JSON-like object literal, indicate auto-approve / auto-start
 * semantics on the MCP / DXT side.
 */
export const AUTO_APPROVE_KEYS: Readonly<Record<string, string>> = {
  autoApprove: "autoApprove",
  auto_approve: "auto_approve",
  autoStart: "autoStart",
  trust: "trust",
  trusted: "trusted",
};

/**
 * Call method names whose AST match flags a bridge / DXT ingress.
 * Keys are lowercased.
 */
export const BRIDGE_METHOD_NAMES: Readonly<Record<string, string>> = {
  sendnativemessage: "chrome/browser runtime.sendNativeMessage",
  handle: "electron ipcMain.handle (when receiver is ipcMain)",
};

/**
 * Receivers that, when observed against `handle()`, promote the
 * match to a DXT privilege-bridge hit.
 */
export const IPC_RECEIVERS: Readonly<Record<string, true>> = {
  ipcMain: true,
  ipcmain: true,
};

/**
 * Receiver path fragments for native-messaging calls.
 */
export const NATIVE_MESSAGING_ROOTS: Readonly<Record<string, true>> = {
  "chrome.runtime": true,
  "browser.runtime": true,
};
