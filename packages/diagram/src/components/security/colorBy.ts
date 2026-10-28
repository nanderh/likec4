import {
  type SecuritySeverity,
  type Threat,
  type Vulnerability,
  highestSeverity,
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
 * - `resolved` if all items are resolved
 * - `none` if there are no items
 */
export type SecurityLevel = SecuritySeverity | 'resolved' | 'none'

/**
 * Colors of {@link SecurityLevel}, injected as additional palette colors (see LikeC4Styles)
 */
export const SecurityPalette = {
  'likec4-security-critical': '#A51D2D',
  'likec4-security-high': '#E5484D',
  'likec4-security-medium': '#FFB224',
  'likec4-security-low': '#30A46C',
  'likec4-security-info': '#8B8D98',
  'likec4-security-resolved': '#3E63DD',
} as const

export type SecurityPaletteColor = keyof typeof SecurityPalette

export const SecurityLevels = ['critical', 'high', 'medium', 'low', 'info', 'resolved', 'none'] as const

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
  const highest = highestSeverity([
    ...vulnerabilities.filter(v => isUnresolvedSecurityStatus(v.status)).map(vulnerabilitySeverity),
    ...threats.filter(t => isUnresolvedSecurityStatus(t.status)).map(threatRisk),
  ])
  if (highest) {
    return highest
  }
  // Unresolved items without severity or risk
  const hasUnresolved = vulnerabilities.some(v => isUnresolvedSecurityStatus(v.status))
    || threats.some(t => isUnresolvedSecurityStatus(t.status))
  return hasUnresolved ? 'info' : 'resolved'
}

export const securityLevelLabels = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Unrated',
  resolved: 'All resolved',
  none: 'Nothing recorded',
} as const satisfies Record<SecurityLevel, string>
