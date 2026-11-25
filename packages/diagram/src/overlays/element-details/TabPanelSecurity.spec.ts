import { Builder } from '@likec4/core/builder'
import { LikeC4Model } from '@likec4/core/model'
import type { Threat } from '@likec4/core/types'
import { describe, expect, it } from 'vitest'
import { securityItemCounts } from './TabPanelSecurity'

const threat = (id: string): Threat => ({ id, stride: ['spoofing'] })

describe('securityItemCounts', () => {
  const data = Builder.specification({ elements: ['system', 'app'] })
    .model(({ system, app, rel }, _) =>
      _(
        system('gateway').with(
          app('vault'),
        ),
        system('pki'),
        system('meter'),
        rel('gateway', 'pki'),
        rel('meter', 'gateway'),
        rel('gateway.vault', 'pki'),
      )
    )
    .build()

  const withThreats = LikeC4Model.create({
    ...data,
    elements: {
      ...data.elements,
      gateway: { ...data.elements['gateway']!, threats: [threat('GW-01'), threat('GW-02')] },
      ['gateway.vault']: { ...data.elements['gateway.vault']!, threats: [threat('SV-01')] },
    },
    relations: Object.fromEntries(
      Object.entries(data.relations).map(([id, rel]) => {
        const source = rel.source.model
        const items = source === 'gateway.vault' ? [threat('DF-VT')] : [threat(`DF-${source}`)]
        return [id, { ...rel, threats: items, vulnerabilities: [{ id: `V-${source}` }] }]
      }),
    ),
  })

  it('counts items of the element, its direct relationships and its children (as listed in the tabs)', () => {
    expect(securityItemCounts(withThreats.element('gateway'))).toEqual({
      // own GW-01, GW-02 + gateway -> pki + meter -> gateway + inherited SV-01
      threats: 5,
      vulnerabilities: 2,
    })
  })

  it('does not count relationships of nested elements to outside', () => {
    expect(securityItemCounts(withThreats.element('gateway.vault'))).toEqual({
      threats: 2,
      vulnerabilities: 1,
    })
  })
})
