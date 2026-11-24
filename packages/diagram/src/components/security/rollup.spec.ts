import { Builder } from '@likec4/core/builder'
import { LikeC4Model } from '@likec4/core/model'
import type { Threat } from '@likec4/core/types'
import { describe, expect, it } from 'vitest'
import {
  elementSecurityScope,
  inheritedSecurityItems,
  ownAndDirectSecurityItems,
  rolledUpSecurityItems,
} from './rollup'

const threat = (id: string, status?: Threat['status']): Threat => ({
  id,
  stride: ['spoofing'],
  ...(status && { status }),
})

describe('security roll-up', () => {
  const data = Builder.specification({ elements: ['system', 'app'] })
    .model(({ system, app, rel }, _) =>
      _(
        system('gateway').with(
          app('keyStore'),
          app('hal'),
        ),
        system('pki'),
        system('meter'),
        // direct, outside the gateway
        rel('gateway', 'pki'),
        rel('meter', 'gateway'),
        // from a child to outside: neither direct nor inside
        rel('gateway.keyStore', 'pki'),
        // between children
        rel('gateway.hal', 'gateway.keyStore'),
      )
    )
    .build()

  const relThreat = (source: string, target: string) => `DF-${source}-${target}`

  const model = LikeC4Model.create({
    ...data,
    elements: {
      ...data.elements,
      gateway: { ...data.elements['gateway']!, threats: [threat('GW-01')] },
      ['gateway.keyStore']: {
        ...data.elements['gateway.keyStore']!,
        threats: [threat('KS-01'), threat('KS-09', 'accepted')],
      },
      ['gateway.hal']: { ...data.elements['gateway.hal']!, vulnerabilities: [{ id: 'V-HAL' }] },
    },
    relations: Object.fromEntries(
      Object.entries(data.relations).map(([id, rel]) => [id, {
        ...rel,
        threats: [threat(relThreat(rel.source.model, rel.target.model))],
      }]),
    ),
  })

  const ids = (items: { threats: ReadonlyArray<Threat>; vulnerabilities: ReadonlyArray<{ id: string }> }) =>
    [...items.threats.map(t => t.id), ...items.vulnerabilities.map(v => v.id)].sort()

  it('separates own, direct and inherited items', () => {
    const scope = elementSecurityScope(model.element('gateway'))
    expect(ids(scope.own)).toEqual(['GW-01'])
    expect(scope.direct.map(r => r.threats[0]!.id).sort()).toEqual([
      relThreat('gateway', 'pki'),
      relThreat('meter', 'gateway'),
    ])
    expect(scope.descendants.map(d => d.element.id)).toEqual(['gateway.hal', 'gateway.keyStore'])
    expect(scope.internal.map(r => r.threats[0]!.id)).toEqual([relThreat('gateway.hal', 'gateway.keyStore')])
    expect(ids(inheritedSecurityItems(scope))).toEqual([
      relThreat('gateway.hal', 'gateway.keyStore'),
      'KS-01',
      'KS-09',
      'V-HAL',
    ])
  })

  it('rolls up items inside the element for a collapsed parent', () => {
    expect(ids(rolledUpSecurityItems(model.element('gateway')))).toEqual([
      relThreat('gateway.hal', 'gateway.keyStore'),
      'GW-01',
      'KS-01',
      'KS-09',
      'V-HAL',
    ])
  })

  it('own and direct items, for the scope of a view without the element', () => {
    expect(ids(ownAndDirectSecurityItems(model.element('gateway')))).toEqual([
      relThreat('gateway', 'pki'),
      'GW-01',
      relThreat('meter', 'gateway'),
    ].sort())
  })

  it('a leaf element rolls up only its own items', () => {
    expect(ids(rolledUpSecurityItems(model.element('gateway.keyStore')))).toEqual(['KS-01', 'KS-09'])
    expect(ids(rolledUpSecurityItems(model.element('pki')))).toEqual([])
  })
})
