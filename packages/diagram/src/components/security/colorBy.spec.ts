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

  it('returns resolved when all items are resolved', () => {
    expect(securityLevel({
      vulnerabilities: [{ id: 'V1', severity: 'high', status: 'mitigated' }],
      threats: [],
    }, 'security')).toBe('resolved')
  })

  it('returns info for unresolved items without rating', () => {
    expect(securityLevel({ vulnerabilities: [], threats: [{ id: 'T1', stride: [] }] }, 'threats')).toBe('info')
  })

  it('returns none without items', () => {
    expect(securityLevel(subject, 'threats')).not.toBe('none')
    expect(securityLevel({ vulnerabilities: [], threats: [] }, 'security')).toBe('none')
    expect(securityLevelColor('none')).toBe('muted')
    expect(securityLevelColor('high')).toBe('likec4-security-high')
  })
})
