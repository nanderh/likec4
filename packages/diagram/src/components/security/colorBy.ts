import {
  type RiskScore,
  type SecuritySeverity,
  type Threat,
  type Vulnerability,
  highestSeverity,
  isRiskCarriedSecurityStatus,
  isUnresolvedSecurityStatus,
  threatRisk,
  threatRiskScore,
  vulnerabilitySeverity,
} from '@likec4/core/types'

/**
 * Colors nodes by security data instead of their own color:
 * - `vulnerabilities`: highest severity of unresolved vulnerabilities
 * - `threats`: highest risk of unresolved threats
 * - `security`: highest of both
 * - `risk-score`: highest likelihood × impact of unresolved threats (1 - 16)
 */
export type ColorByMode = 'default' | 'vulnerabilities' | 'threats' | 'security' | 'risk-score'

export const ColorByModes: ReadonlyArray<ColorByMode> = [
  'default',
  'vulnerabilities',
  'threats',
  'security',
  'risk-score',
]

export type RiskScoreLevel = `score-${RiskScore}`

/**
 * Level used to color a node in "color by" modes:
 * - severity of the most critical unresolved item, or its risk score in `risk-score` mode
 * - `info` if unresolved items are not rated
 * - `carried` if nothing is unresolved, but some risk is accepted or transferred
 * - `closed` if all items are closed (mitigated, resolved, false positive)
 * - `none` if there are no items
 */
export type SecurityLevel = SecuritySeverity | RiskScoreLevel | 'carried' | 'closed' | 'none'

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
  // risk score, likelihood × impact: green - yellow - red - dark red
  'likec4-security-score-1': '#30A46C',
  'likec4-security-score-2': '#65BA43',
  'likec4-security-score-3': '#A3C43B',
  'likec4-security-score-4': '#E2C524',
  'likec4-security-score-6': '#FFA01C',
  'likec4-security-score-8': '#F76B15',
  'likec4-security-score-9': '#E5484D',
  'likec4-security-score-12': '#C2253A',
  'likec4-security-score-16': '#7F1426',
} as const satisfies Record<`likec4-security-${Exclude<SecurityLevel, 'none'>}`, string>

export type SecurityPaletteColor = keyof typeof SecurityPalette

/**
 * Levels of the severity and risk modes, in legend order
 */
export const SecurityLevels = ['critical', 'high', 'medium', 'low', 'info', 'carried', 'closed', 'none'] as const

/**
 * Levels of the `risk-score` mode besides the scores, in legend order
 */
export const RiskScoreOtherLevels = ['info', 'carried', 'closed', 'none'] as const

export function riskScoreLevel(score: RiskScore): RiskScoreLevel {
  return `score-${score}`
}

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

function highestRiskScore(threats: ReadonlyArray<Threat>): RiskScore | null {
  let highest: RiskScore | null = null
  for (const t of threats) {
    const score = threatRiskScore(t)
    if (score && (!highest || score > highest)) {
      highest = score
    }
  }
  return highest
}

export function securityLevel(subject: WithSecurity, mode: Exclude<ColorByMode, 'default'>): SecurityLevel {
  // Risk score uses likelihood and impact, vulnerabilities have neither
  const vulnerabilities = mode === 'threats' || mode === 'risk-score' ? [] : subject.vulnerabilities
  const threats = mode === 'vulnerabilities' ? [] : subject.threats
  if (vulnerabilities.length === 0 && threats.length === 0) {
    return 'none'
  }
  const unresolvedVulnerabilities = vulnerabilities.filter(v => isUnresolvedSecurityStatus(v.status))
  const unresolvedThreats = threats.filter(t => isUnresolvedSecurityStatus(t.status))
  if (mode === 'risk-score' && unresolvedThreats.length > 0) {
    const score = highestRiskScore(unresolvedThreats)
    return score ? riskScoreLevel(score) : 'info'
  }
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
  'score-1': 'Score 1',
  'score-2': 'Score 2',
  'score-3': 'Score 3',
  'score-4': 'Score 4',
  'score-6': 'Score 6',
  'score-8': 'Score 8',
  'score-9': 'Score 9',
  'score-12': 'Score 12',
  'score-16': 'Score 16',
} as const satisfies Record<SecurityLevel, string>
