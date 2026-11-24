import { describe, expect, it } from 'vitest'
import {
  cvssToSeverity,
  highestSeverity,
  isRiskCarriedSecurityStatus,
  isUnresolvedSecurityStatus,
  parseStrideCategory,
  RiskScores,
  securityStatusGroup,
  threatRisk,
  threatRiskScore,
  vulnerabilitySeverity,
} from './model-security'

describe('model-security', () => {
  it('parseStrideCategory', () => {
    expect(parseStrideCategory('S')).toBe('spoofing')
    expect(parseStrideCategory('e')).toBe('elevation-of-privilege')
    expect(parseStrideCategory('tampering')).toBe('tampering')
    expect(parseStrideCategory('informationDisclosure')).toBe('information-disclosure')
    expect(parseStrideCategory('denial_of_service')).toBe('denial-of-service')
    expect(parseStrideCategory('DoS')).toBe('denial-of-service')
    expect(parseStrideCategory('X')).toBeNull()
    expect(parseStrideCategory('phishing')).toBeNull()
  })

  it('threatRisk derives risk from likelihood and impact', () => {
    expect(threatRisk({ likelihood: 'low', impact: 'low' })).toBe('low')
    expect(threatRisk({ likelihood: 'low', impact: 'high' })).toBe('medium')
    expect(threatRisk({ likelihood: 'medium', impact: 'medium' })).toBe('medium')
    expect(threatRisk({ likelihood: 'medium', impact: 'high' })).toBe('high')
    expect(threatRisk({ likelihood: 'high', impact: 'high' })).toBe('critical')
    expect(threatRisk({ likelihood: 'low', impact: 'critical' })).toBe('medium')
    expect(threatRisk({ impact: 'high' })).toBe('high')
    expect(threatRisk({})).toBeNull()
  })

  it('threatRisk prefers explicit risk', () => {
    expect(threatRisk({ likelihood: 'high', impact: 'high', risk: 'low' })).toBe('low')
  })

  it('cvssToSeverity follows CVSS v3 ratings', () => {
    expect(cvssToSeverity(0)).toBe('info')
    expect(cvssToSeverity(3.9)).toBe('low')
    expect(cvssToSeverity(4)).toBe('medium')
    expect(cvssToSeverity(7)).toBe('high')
    expect(cvssToSeverity(9)).toBe('critical')
  })

  it('vulnerabilitySeverity prefers explicit severity', () => {
    expect(vulnerabilitySeverity({ cvss: 9.8 })).toBe('critical')
    expect(vulnerabilitySeverity({ severity: 'low', cvss: 9.8 })).toBe('low')
    expect(vulnerabilitySeverity({})).toBeNull()
  })

  it('highestSeverity', () => {
    expect(highestSeverity(['low', null, 'high', 'medium'])).toBe('high')
    expect(highestSeverity([])).toBeNull()
  })

  it('isUnresolvedSecurityStatus', () => {
    expect(isUnresolvedSecurityStatus(undefined)).toBe(true)
    expect(isUnresolvedSecurityStatus('open')).toBe(true)
    expect(isUnresolvedSecurityStatus('in-progress')).toBe(true)
    expect(isUnresolvedSecurityStatus('mitigated')).toBe(false)
    expect(isUnresolvedSecurityStatus('false-positive')).toBe(false)
    expect(isUnresolvedSecurityStatus('accepted')).toBe(false)
  })

  it('threatRiskScore multiplies likelihood and impact', () => {
    expect(threatRiskScore({ likelihood: 'low', impact: 'low' })).toBe(1)
    expect(threatRiskScore({ likelihood: 'medium', impact: 'high' })).toBe(6)
    expect(threatRiskScore({ likelihood: 'low', impact: 'critical' })).toBe(4)
    expect(threatRiskScore({ likelihood: 'critical', impact: 'critical' })).toBe(16)
    // likelihood x impact wins over an explicit risk level
    expect(threatRiskScore({ likelihood: 'high', impact: 'high', risk: 'low' })).toBe(9)
  })

  it('threatRiskScore falls back to the risk level', () => {
    expect(threatRiskScore({ risk: 'high' })).toBe(9)
    expect(threatRiskScore({ impact: 'medium' })).toBe(4)
    expect(threatRiskScore({})).toBeNull()
    for (const l of ['low', 'medium', 'high', 'critical'] as const) {
      for (const i of ['low', 'medium', 'high', 'critical'] as const) {
        expect(RiskScores).toContain(threatRiskScore({ likelihood: l, impact: i }))
      }
    }
  })

  it('securityStatusGroup separates carried risk from closed', () => {
    expect(securityStatusGroup(undefined)).toBe('unresolved')
    expect(securityStatusGroup('open')).toBe('unresolved')
    expect(securityStatusGroup('in-progress')).toBe('unresolved')
    expect(securityStatusGroup('accepted')).toBe('carried')
    expect(securityStatusGroup('transferred')).toBe('carried')
    expect(securityStatusGroup('mitigated')).toBe('closed')
    expect(securityStatusGroup('resolved')).toBe('closed')
    expect(securityStatusGroup('false-positive')).toBe('closed')
    expect(isRiskCarriedSecurityStatus('accepted')).toBe(true)
    expect(isRiskCarriedSecurityStatus('mitigated')).toBe(false)
  })
})
