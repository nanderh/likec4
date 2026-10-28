import type { Link } from './_common'
import type { MarkdownOrString } from './scalar'

/**
 * STRIDE threat categories
 * @see https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
 */
export const StrideCategories = [
  'spoofing',
  'tampering',
  'repudiation',
  'information-disclosure',
  'denial-of-service',
  'elevation-of-privilege',
] as const
export type StrideCategory = typeof StrideCategories[number]

/**
 * Single letter abbreviations of {@link StrideCategories}
 */
export const StrideLetters = {
  'spoofing': 'S',
  'tampering': 'T',
  'repudiation': 'R',
  'information-disclosure': 'I',
  'denial-of-service': 'D',
  'elevation-of-privilege': 'E',
} as const satisfies Record<StrideCategory, string>

export const StrideTitles = {
  'spoofing': 'Spoofing',
  'tampering': 'Tampering',
  'repudiation': 'Repudiation',
  'information-disclosure': 'Information disclosure',
  'denial-of-service': 'Denial of service',
  'elevation-of-privilege': 'Elevation of privilege',
} as const satisfies Record<StrideCategory, string>

/**
 * Security property violated by each STRIDE category
 */
export const StrideProperties = {
  'spoofing': 'Authentication',
  'tampering': 'Integrity',
  'repudiation': 'Non-repudiation',
  'information-disclosure': 'Confidentiality',
  'denial-of-service': 'Availability',
  'elevation-of-privilege': 'Authorization',
} as const satisfies Record<StrideCategory, string>

/**
 * Converts a full category name, a single letter (`S`, `T`, ...) or a
 * camel/snake case variant (`informationDisclosure`, `denial_of_service`) to {@link StrideCategory}.
 * Returns null if value is not recognized.
 */
export function parseStrideCategory(value: string): StrideCategory | null {
  const normalized = value
    .trim()
    .replace(/([a-z])([A-Z])/g, '$1-$2')
    .replace(/[\s_]+/g, '-')
    .toLowerCase()
  if (normalized.length === 1) {
    for (const category of StrideCategories) {
      if (StrideLetters[category].toLowerCase() === normalized) {
        return category
      }
    }
    return null
  }
  switch (value.trim().toLowerCase()) {
    case 'information':
    case 'disclosure':
      return 'information-disclosure'
    case 'dos':
    case 'denial':
      return 'denial-of-service'
    case 'elevation':
    case 'eop':
      return 'elevation-of-privilege'
  }
  return StrideCategories.find(c => c === normalized) ?? null
}

/**
 * Severity of a vulnerability, aligned with CVSS v3 qualitative ratings
 */
export const SecuritySeverities = ['critical', 'high', 'medium', 'low', 'info'] as const
export type SecuritySeverity = typeof SecuritySeverities[number]

/**
 * Qualitative level, used for likelihood, impact and risk of a threat
 */
export const RiskLevels = ['critical', 'high', 'medium', 'low'] as const
export type RiskLevel = typeof RiskLevels[number]

/**
 * Lifecycle status of a vulnerability or threat
 */
export const SecurityStatuses = [
  'open',
  'in-progress',
  'mitigated',
  'accepted',
  'transferred',
  'resolved',
  'false-positive',
] as const
export type SecurityStatus = typeof SecurityStatuses[number]

/**
 * Known vulnerability (e.g. CVE, pentest finding) affecting an element or a relationship
 */
export interface Vulnerability {
  /**
   * Identifier, e.g. `CVE-2024-3094`, `GHSA-...` or internal `VULN-001`
   */
  readonly id: string
  readonly title?: string | null
  readonly severity?: SecuritySeverity | null
  /**
   * CVSS base score, 0.0 - 10.0
   */
  readonly cvss?: number | null
  /**
   * CVSS vector string, e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
   */
  readonly vector?: string | null
  /**
   * Weakness identifier, e.g. `CWE-79`
   */
  readonly cwe?: string | null
  readonly status?: SecurityStatus | null
  readonly description?: MarkdownOrString | null
  readonly mitigation?: MarkdownOrString | null
  readonly links?: readonly Link[] | null
}

/**
 * Threat identified during STRIDE threat modelling
 */
export interface Threat {
  /**
   * Identifier, e.g. `T-001`
   */
  readonly id: string
  readonly title?: string | null
  readonly stride: readonly StrideCategory[]
  readonly likelihood?: RiskLevel | null
  readonly impact?: RiskLevel | null
  /**
   * Explicit risk level, if not set it is derived from likelihood and impact
   * @see {@link threatRisk}
   */
  readonly risk?: RiskLevel | null
  readonly status?: SecurityStatus | null
  readonly description?: MarkdownOrString | null
  readonly mitigation?: MarkdownOrString | null
  readonly links?: readonly Link[] | null
}

export type WithSecurity = {
  readonly vulnerabilities?: readonly Vulnerability[] | null
  readonly threats?: readonly Threat[] | null
}

const levelScore = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
} as const satisfies Record<RiskLevel, number>

/**
 * Returns explicit risk of the threat, or derives it from likelihood and impact (risk matrix).
 * If only one of them is defined, it is used as the risk.
 */
export function threatRisk(threat: Pick<Threat, 'likelihood' | 'impact' | 'risk'>): RiskLevel | null {
  const { likelihood, impact, risk } = threat
  switch (true) {
    case !!risk:
      return risk
    case !!likelihood && !!impact: {
      const score = levelScore[likelihood] * levelScore[impact]
      switch (true) {
        case score >= 9:
          return 'critical'
        case score >= 6:
          return 'high'
        case score >= 3:
          return 'medium'
        default:
          return 'low'
      }
    }
    default:
      return likelihood ?? impact ?? null
  }
}

/**
 * Converts CVSS base score to qualitative severity rating (CVSS v3)
 */
export function cvssToSeverity(score: number): SecuritySeverity {
  switch (true) {
    case score >= 9:
      return 'critical'
    case score >= 7:
      return 'high'
    case score >= 4:
      return 'medium'
    case score > 0:
      return 'low'
    default:
      return 'info'
  }
}

/**
 * Returns explicit severity of the vulnerability, or derives it from CVSS score
 */
export function vulnerabilitySeverity(
  vulnerability: Pick<Vulnerability, 'severity' | 'cvss'>,
): SecuritySeverity | null {
  return vulnerability.severity ?? (vulnerability.cvss != null ? cvssToSeverity(vulnerability.cvss) : null)
}

/**
 * Returns true if status means the issue is still to be addressed (`open`, `in-progress` or not set)
 */
export function isUnresolvedSecurityStatus(status: SecurityStatus | null | undefined): boolean {
  return !status || status === 'open' || status === 'in-progress'
}

const severityRank = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
} as const satisfies Record<SecuritySeverity, number>

/**
 * Compares severities, higher severity first (for sorting)
 */
export function compareSeverity(
  a: SecuritySeverity | null | undefined,
  b: SecuritySeverity | null | undefined,
): number {
  return (b ? severityRank[b] : 0) - (a ? severityRank[a] : 0)
}

/**
 * Returns the highest severity from the list, or null if list is empty
 */
export function highestSeverity(
  severities: Iterable<SecuritySeverity | null | undefined>,
): SecuritySeverity | null {
  let highest: SecuritySeverity | null = null
  for (const s of severities) {
    if (s && (!highest || severityRank[s] > severityRank[highest])) {
      highest = s
    }
  }
  return highest
}
