import { describe, expect, it } from 'vitest'
import { securityBadgeSummary } from './summary'

describe('securityBadgeSummary', () => {
  it('counts unresolved items and carried risk separately', () => {
    // like gateway.keyStore: KS-09 accepted, other threats open
    expect(securityBadgeSummary({
      vulnerabilities: [],
      threats: [
        { id: 'KS-01', stride: [], risk: 'high', status: 'open' },
        { id: 'KS-02', stride: [], risk: 'medium', status: 'in-progress' },
        { id: 'KS-09', stride: [], risk: 'critical', status: 'accepted' },
        { id: 'KS-10', stride: [], risk: 'critical', status: 'mitigated' },
      ],
    })).toEqual({
      threats: 2,
      vulnerabilities: 0,
      carried: 1,
      severity: 'high',
    })
  })

  it('shows carried risk without unresolved items', () => {
    // like pki.validationAuthority: only VA-01 accepted
    expect(securityBadgeSummary({
      vulnerabilities: [{ id: 'V1', status: 'transferred' }],
      threats: [{ id: 'VA-01', stride: [], status: 'accepted' }],
    })).toEqual({
      threats: 0,
      vulnerabilities: 0,
      carried: 2,
      severity: null,
    })
  })

  it('returns null when everything is closed', () => {
    expect(securityBadgeSummary({
      vulnerabilities: [{ id: 'V1', status: 'resolved' }],
      threats: [{ id: 'T1', stride: [], status: 'false-positive' }],
    })).toBeNull()
    expect(securityBadgeSummary({ vulnerabilities: [], threats: [] })).toBeNull()
  })
})
