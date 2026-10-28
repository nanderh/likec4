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
          app('keyStore'),
        ),
        system('pki'),
        system('meter'),
        rel('gateway', 'pki'),
        rel('meter', 'gateway'),
        rel('gateway.keyStore', 'pki'),
      )
    )
    .build()

  const withThreats = LikeC4Model.create({
    ...data,
    elements: {
      ...data.elements,
      gateway: { ...data.elements['gateway']!, threats: [threat('GW-01'), threat('GW-02')] },
      ['gateway.keyStore']: { ...data.elements['gateway.keyStore']!, threats: [threat('KS-01')] },
    },
    relations: Object.fromEntries(
      Object.entries(data.relations).map(([id, rel]) => {
        const source = rel.source.model
        const items = source === 'gateway.keyStore' ? [threat('DF-KS')] : [threat(`DF-${source}`)]
        return [id, { ...rel, threats: items, vulnerabilities: [{ id: `V-${source}` }] }]
      }),
    ),
  })

  it('counts items of the element and its direct relationships (as listed in the tabs)', () => {
    expect(securityItemCounts(withThreats.element('gateway'))).toEqual({
      // own GW-01, GW-02 + gateway -> pki + meter -> gateway
      threats: 4,
      vulnerabilities: 2,
    })
  })

  it('does not count relationships of nested elements', () => {
    expect(securityItemCounts(withThreats.element('gateway.keyStore'))).toEqual({
      threats: 2,
      vulnerabilities: 1,
    })
  })
})
