/**
 * Engine Registry — 5 specialized analysis engines
 *
 * Each engine owns a category of rules and implements real analysis:
 * - CodeAnalyzer: AST taint tracking, secret entropy detection
 * - DescriptionAnalyzer: Linguistic injection scoring, Unicode analysis
 * - SchemaAnalyzer: Structural inference, annotation consistency
 * - DependencyAnalyzer: Multi-algorithm similarity, CVE lookup
 * - ProtocolAnalyzer: Transport security, OAuth analysis, H2 injection
 */

export { CodeAnalyzer, type CodeFinding } from "./code-analyzer.js";
export { DescriptionAnalyzer, type DescriptionFinding } from "./description-analyzer.js";
export { SchemaAnalyzer, type SchemaFinding } from "./schema-analyzer.js";
export { DependencyAnalyzer, type DependencyFinding } from "./dependency-analyzer.js";
export { ProtocolAnalyzer, type ProtocolFinding } from "./protocol-analyzer.js";
