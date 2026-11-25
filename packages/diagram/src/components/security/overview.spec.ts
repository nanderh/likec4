import { Builder } from '@likec4/core/builder'
import { LikeC4Model } from '@likec4/core/model'
import { describe, expect, it } from 'vitest'
import {
  countRisk,
  countRiskMatrix,
  countStatusGroups,
  countStride,
  NotClosedStatuses,
  pickRegisterView,
  statusesOfGroups,
  topOwners,
} from './overview'
import { buildSecurityRegister } from './register'

function testModel() {
  const { $data: data } = Builder.specification({ elements: ['system', 'component'] })
    .model(({ system, component, rel }, _) =>
      _(
        system('gateway').with(
          component('vault'),
        ),
        system('pki'),
        rel('gateway', 'pki', 'CMP'),
      )
    )
    .views(({ view, viewOf, $include }, _) =>
      _(
        view('index').with($include('*')),
        viewOf('gatewayView', 'gateway').with($include('*')),
      )
    )
    .toLikeC4Model()

  return LikeC4Model.create({
    ...data,
    elements: {
      ...data.elements,
      ['gateway.vault']: {
        ...data.elements['gateway.vault']!,
        threats: [
          { id: 'SV-01', stride: ['information-disclosure', 'spoofing'], likelihood: 'low', impact: 'critical' },
          { id: 'SV-02', stride: ['tampering'], likelihood: 'low', impact: 'critical', status: 'in-progress' },
          { id: 'SV-09', stride: ['tampering'], risk: 'high', status: 'accepted' },
          { id: 'SV-10', stride: ['tampering'], likelihood: 'high', impact: 'high', status: 'mitigated' },
          { id: 'SV-11', stride: [] },
        ],
      },
      pki: {
        ...data.elements['pki']!,
        vulnerabilities: [{ id: 'CVE-2024-3094', severity: 'critical' }],
      },
    },
    relations: Object.fromEntries(
      Object.entries(data.relations).map(([id, rel]) => [id, {
        ...rel,
        threats: [
          { id: 'DF-01', stride: ['denial-of-service'], likelihood: 'medium', impact: 'medium' },
        ],
      }]),
    ),
  })
}

describe('security overview', () => {
  const model = testModel()
  const rows = buildSecurityRegister(model)

  it('groups statuses', () => {
    expect(statusesOfGroups('carried')).toEqual(['accepted', 'transferred'])
    expect(NotClosedStatuses).toEqual(['open', 'in-progress', 'accepted', 'transferred'])
    expect(countStatusGroups(rows)).toEqual({ unresolved: 5, carried: 1, closed: 1 })
  })

  it('places threats that are not closed on the risk matrix', () => {
    expect(countRiskMatrix(rows)).toEqual({
      cells: {
        'low:critical': 2,
        'medium:medium': 1,
      },
      riskOnly: 1,
      unrated: 1,
    })
  })

  it('counts risk of items that are not closed', () => {
    expect(countRisk(rows)).toEqual({
      critical: 1,
      high: 1,
      medium: 3,
      low: 0,
      info: 0,
      none: 1,
    })
  })

  it('counts threats per STRIDE category and status group', () => {
    const stride = countStride(rows)
    expect(stride.tampering).toEqual({ unresolved: 1, carried: 1, closed: 1 })
    expect(stride.spoofing).toEqual({ unresolved: 1, carried: 0, closed: 0 })
    expect(stride.repudiation).toEqual({ unresolved: 0, carried: 0, closed: 0 })
  })

  it('ranks owners by items not closed, then by risk', () => {
    const owners = topOwners(rows, 10)
    expect(owners.map(o => [o.owner.label, o.counts.unresolved + o.counts.carried, o.highestRisk])).toEqual([
      ['vault (gateway.vault)', 4, 'high'],
      ['pki', 1, 'critical'],
      ['gateway → pki: CMP', 1, 'medium'],
    ])
    expect(topOwners(rows, 1)).toHaveLength(1)
  })

  it('picks the view of the scope element', () => {
    const vault = model.element('gateway.vault')
    expect(pickRegisterView(model.element('gateway').views(), { scope: 'gateway' as never })?.id).toBe('gatewayView')
    expect(pickRegisterView(vault.views(), { currentViewId: 'index' })?.id).toBe('gatewayView')
    expect(pickRegisterView(model.element('pki').views(), { currentViewId: 'index' })?.id).toBe('index')
    expect(pickRegisterView([])).toBeNull()
  })
})
