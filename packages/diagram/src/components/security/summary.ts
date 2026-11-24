import {
  type SecuritySeverity,
  type Threat,
  type Vulnerability,
  highestSeverity,
  securityStatusGroup,
  threatRisk,
  vulnerabilitySeverity,
} from '@likec4/core/types'

export type SecurityItemsSubject = {
  readonly vulnerabilities: ReadonlyArray<Vulnerability>
  readonly threats: ReadonlyArray<Threat>
}

/**
 * Counts for the security badge of a node
 */
export interface SecurityBadgeSummary {
  /**
   * Unresolved threats (`open`, `in-progress`)
   */
  readonly threats: number
  /**
   * Unresolved vulnerabilities (`open`, `in-progress`)
   */
  readonly vulnerabilities: number
  /**
   * Threats and vulnerabilities with carried risk (`accepted`, `transferred`)
   */
  readonly carried: number
  /**
   * Highest severity or risk of the unresolved items
   */
  readonly severity: SecuritySeverity | null
}

/**
 * Summarizes threats and vulnerabilities for the node badge.
 * Returns null if there is nothing unresolved and no carried risk (everything is closed, or no items).
 */
export function securityBadgeSummary(subject: SecurityItemsSubject): SecurityBadgeSummary | null {
  const unresolvedThreats = subject.threats.filter(t => securityStatusGroup(t.status) === 'unresolved')
  const unresolvedVulnerabilities = subject.vulnerabilities.filter(v => securityStatusGroup(v.status) === 'unresolved')
  const carried = subject.threats.filter(t => securityStatusGroup(t.status) === 'carried').length
    + subject.vulnerabilities.filter(v => securityStatusGroup(v.status) === 'carried').length
  if (unresolvedThreats.length === 0 && unresolvedVulnerabilities.length === 0 && carried === 0) {
    return null
  }
  return {
    threats: unresolvedThreats.length,
    vulnerabilities: unresolvedVulnerabilities.length,
    carried,
    severity: highestSeverity([
      ...unresolvedThreats.map(threatRisk),
      ...unresolvedVulnerabilities.map(vulnerabilitySeverity),
    ]),
  }
}
