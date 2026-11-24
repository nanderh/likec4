import { describe, expect, it } from 'vitest'
import { securityLevel, securityLevelColor } from './colorBy'

describe('securityLevel', () => {
  const subject = {
    vulnerabilities: [
      { id: 'V1', severity: 'medium' as const },
      { id: 'V2', severity: 'critical' as const, status: 'resolved' as const },
    ],
    threats: [
      { id: 'T1', stride: ['spoofing' as const], likelihood: 'high' as const, impact: 'high' as const },
    ],
  }

  it('uses highest unresolved item of the selected kind', () => {
    expect(securityLevel(subject, 'vulnerabilities')).toBe('medium')
    expect(securityLevel(subject, 'threats')).toBe('critical')
    expect(securityLevel(subject, 'security')).toBe('critical')
  })

  it('returns closed when all items are closed', () => {
    expect(securityLevel({
      vulnerabilities: [{ id: 'V1', severity: 'high', status: 'mitigated' }],
      threats: [{ id: 'T1', stride: [], status: 'false-positive' }],
    }, 'security')).toBe('closed')
  })

  it('returns carried when only accepted or transferred items remain', () => {
    // like pki.validationAuthority: a single accepted threat
    expect(securityLevel({
      vulnerabilities: [],
      threats: [{ id: 'VA-01', stride: [], likelihood: 'high', impact: 'high', status: 'accepted' }],
    }, 'threats')).toBe('carried')
    expect(securityLevel({
      vulnerabilities: [{ id: 'V1', severity: 'high', status: 'transferred' }],
      threats: [{ id: 'T1', stride: [], status: 'mitigated' }],
    }, 'security')).toBe('carried')
    expect(securityLevelColor('carried')).toBe('likec4-security-carried')
  })

  it('unresolved items win over carried items', () => {
    // like gateway.keyStore: KS-09 accepted, other threats open
    expect(securityLevel({
      vulnerabilities: [],
      threats: [
        { id: 'KS-09', stride: [], risk: 'critical', status: 'accepted' },
        { id: 'KS-01', stride: [], risk: 'medium', status: 'open' },
      ],
    }, 'threats')).toBe('medium')
  })

  it('returns info for unresolved items without rating', () => {
    expect(securityLevel({ vulnerabilities: [], threats: [{ id: 'T1', stride: [] }] }, 'threats')).toBe('info')
  })

  it('risk-score uses the highest likelihood x impact of unresolved threats', () => {
    const threats = [
      { id: 'T1', stride: [], likelihood: 'medium', impact: 'high', status: 'open' },
      { id: 'T2', stride: [], likelihood: 'high', impact: 'high', status: 'in-progress' },
      { id: 'T3', stride: [], likelihood: 'critical', impact: 'critical', status: 'mitigated' },
    ] as const
    expect(securityLevel({ vulnerabilities: [], threats }, 'risk-score')).toBe('score-9')
    expect(securityLevelColor('score-9')).toBe('likec4-security-score-9')
    // the same threats are all "critical" by risk level
    expect(securityLevel({ vulnerabilities: [], threats: threats.slice(1) }, 'threats')).toBe('critical')
  })

  it('risk-score ignores vulnerabilities and falls back for unrated threats', () => {
    expect(securityLevel({
      vulnerabilities: [{ id: 'V1', severity: 'critical' }],
      threats: [],
    }, 'risk-score')).toBe('none')
    expect(securityLevel({
      vulnerabilities: [],
      threats: [{ id: 'T1', stride: [] }],
    }, 'risk-score')).toBe('info')
    expect(securityLevel({
      vulnerabilities: [],
      threats: [{ id: 'T1', stride: [], risk: 'medium' }],
    }, 'risk-score')).toBe('score-4')
    expect(securityLevel({
      vulnerabilities: [],
      threats: [{ id: 'T1', stride: [], likelihood: 'high', impact: 'high', status: 'accepted' }],
    }, 'risk-score')).toBe('carried')
  })

  it('returns none without items', () => {
    expect(securityLevel(subject, 'threats')).not.toBe('none')
    expect(securityLevel({ vulnerabilities: [], threats: [] }, 'security')).toBe('none')
    expect(securityLevelColor('none')).toBe('muted')
    expect(securityLevelColor('high')).toBe('likec4-security-high')
  })
})
