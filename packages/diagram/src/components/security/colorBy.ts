import {
  type SecuritySeverity,
  type Threat,
  type Vulnerability,
  highestSeverity,
  isRiskCarriedSecurityStatus,
  isUnresolvedSecurityStatus,
  threatRisk,
  vulnerabilitySeverity,
} from '@likec4/core/types'

/**
 * Colors nodes by security data instead of their own color:
 * - `vulnerabilities`: highest severity of unresolved vulnerabilities
 * - `threats`: highest risk of unresolved threats
 * - `security`: highest of both
 */
export type ColorByMode = 'default' | 'vulnerabilities' | 'threats' | 'security'

export const ColorByModes: ReadonlyArray<ColorByMode> = ['default', 'vulnerabilities', 'threats', 'security']

/**
 * Level used to color a node in "color by" modes:
 * - severity of the most critical unresolved item
 * - `carried` if nothing is unresolved, but some risk is accepted or transferred
 * - `closed` if all items are closed (mitigated, resolved, false positive)
 * - `none` if there are no items
 */
export type SecurityLevel = SecuritySeverity | 'carried' | 'closed' | 'none'

/**
 * Colors of {@link SecurityLevel}, injected as additional palette colors (see LikeC4Styles)
 */
export const SecurityPalette = {
  'likec4-security-critical': '#A51D2D',
  'likec4-security-high': '#E5484D',
  'likec4-security-medium': '#FFB224',
  'likec4-security-low': '#30A46C',
  'likec4-security-info': '#8B8D98',
  'likec4-security-carried': '#8E4EC6',
  'likec4-security-closed': '#3E63DD',
} as const

export type SecurityPaletteColor = keyof typeof SecurityPalette

export const SecurityLevels = ['critical', 'high', 'medium', 'low', 'info', 'carried', 'closed', 'none'] as const

/**
 * Returns palette color of the level, `muted` (theme color) if there is nothing to show
 */
export function securityLevelColor(level: SecurityLevel): SecurityPaletteColor | 'muted' {
  return level === 'none' ? 'muted' : `likec4-security-${level}`
}

type WithSecurity = {
  readonly vulnerabilities: ReadonlyArray<Vulnerability>
  readonly threats: ReadonlyArray<Threat>
}

export function securityLevel(subject: WithSecurity, mode: Exclude<ColorByMode, 'default'>): SecurityLevel {
  const vulnerabilities = mode === 'threats' ? [] : subject.vulnerabilities
  const threats = mode === 'vulnerabilities' ? [] : subject.threats
  if (vulnerabilities.length === 0 && threats.length === 0) {
    return 'none'
  }
  const unresolvedVulnerabilities = vulnerabilities.filter(v => isUnresolvedSecurityStatus(v.status))
  const unresolvedThreats = threats.filter(t => isUnresolvedSecurityStatus(t.status))
  if (unresolvedVulnerabilities.length > 0 || unresolvedThreats.length > 0) {
    // Unresolved items without severity or risk are "unrated"
    return highestSeverity([
      ...unresolvedVulnerabilities.map(vulnerabilitySeverity),
      ...unresolvedThreats.map(threatRisk),
    ]) ?? 'info'
  }
  const hasCarried = vulnerabilities.some(v => isRiskCarriedSecurityStatus(v.status))
    || threats.some(t => isRiskCarriedSecurityStatus(t.status))
  return hasCarried ? 'carried' : 'closed'
}

export const securityLevelLabels = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Unrated',
  carried: 'Risk carried only (accepted, transferred)',
  closed: 'All closed (mitigated, resolved)',
  none: 'Nothing recorded',
} as const satisfies Record<SecurityLevel, string>
