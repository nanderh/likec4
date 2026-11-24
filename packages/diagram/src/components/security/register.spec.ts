import { Builder } from '@likec4/core/builder'
import { LikeC4Model } from '@likec4/core/model'
import { describe, expect, it } from 'vitest'
import {
  type RegisterRow,
  buildSecurityRegister,
  filterRegister,
  registerToCsv,
  sortRegister,
} from './register'

function testModel() {
  const data = Builder.specification({ elements: ['system', 'component'] })
    .model(({ system, component, rel }, _) =>
      _(
        system('gateway').with(
          component('keyStore'),
        ),
        system('pki'),
        rel('gateway', 'pki', 'CMP'),
      )
    )
    .build()

  // Builder has no helpers for threats, add them to the data
  return LikeC4Model.create({
    ...data,
    elements: {
      ...data.elements,
      ['gateway.keyStore']: {
        ...data.elements['gateway.keyStore']!,
        threats: [
          {
            id: 'KS-01',
            title: 'Key extraction',
            stride: ['information-disclosure', 'spoofing'],
            likelihood: 'low',
            impact: 'critical',
            status: 'open',
            source: ['Fuse Programming', 'Questions'],
          },
          { id: 'KS-09', title: 'Key material, "persisted"', stride: ['tampering'], risk: 'high', status: 'accepted' },
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
          { id: 'DF-01', title: 'DoS on CMP', stride: ['denial-of-service'], likelihood: 'medium', impact: 'medium' },
        ],
      }]),
    ),
  })
}

describe('security register', () => {
  const model = testModel()
  const rows = buildSecurityRegister(model)

  const ids = (rows: RegisterRow[]) => rows.map(r => r.id)

  it('collects items of elements and relationships', () => {
    expect(rows).toHaveLength(4)
    const ks01 = rows.find(r => r.id === 'KS-01')!
    expect(ks01).toMatchObject({
      kind: 'threat',
      owner: { type: 'element', fqn: 'gateway.keyStore' },
      risk: 'medium',
      status: 'open',
      statusGroup: 'unresolved',
    })
    expect(rows.find(r => r.id === 'DF-01')).toMatchObject({
      owner: { type: 'relationship', source: 'gateway', target: 'pki', label: 'gateway → pki: CMP' },
      status: 'open',
      risk: 'medium',
    })
    expect(rows.find(r => r.id === 'CVE-2024-3094')).toMatchObject({
      kind: 'vulnerability',
      risk: 'critical',
      stride: [],
    })
    expect(rows.find(r => r.id === 'KS-09')?.statusGroup).toBe('carried')
  })

  it('sorts by risk, high first when descending, empty last', () => {
    expect(ids(sortRegister(rows, { column: 'risk', direction: 'desc' }))).toEqual([
      'CVE-2024-3094',
      'KS-09',
      'DF-01',
      'KS-01',
    ])
    expect(ids(sortRegister(rows, { column: 'id', direction: 'asc' }))).toEqual([
      'CVE-2024-3094',
      'DF-01',
      'KS-01',
      'KS-09',
    ])
  })

  it('sorts by status in lifecycle order', () => {
    expect(sortRegister(rows, { column: 'status', direction: 'asc' }).map(r => r.status)).toEqual([
      'open',
      'open',
      'open',
      'accepted',
    ])
  })

  it('filters by text and by values', () => {
    expect(ids(filterRegister(rows, { owner: 'keystore' }))).toEqual(['KS-01', 'KS-09'])
    expect(ids(filterRegister(rows, { stride: ['spoofing', 'denial-of-service'] }))).toEqual(['KS-01', 'DF-01'])
    expect(ids(filterRegister(rows, { kind: ['vulnerability'] }))).toEqual(['CVE-2024-3094'])
    expect(ids(filterRegister(rows, { likelihood: ['none'] }))).toEqual(['KS-09', 'CVE-2024-3094'])
    expect(ids(filterRegister(rows, { status: ['accepted'], title: 'key' }))).toEqual(['KS-09'])
    expect(filterRegister(rows, { status: [] })).toHaveLength(4)
    expect(ids(filterRegister(rows, { source: 'question' }))).toEqual(['KS-01'])
  })

  it('exports CSV with quoting', () => {
    const csv = registerToCsv(sortRegister(rows, { column: 'id', direction: 'asc' }))
    const lines = csv.trimEnd().split('\r\n')
    expect(lines[0]).toBe('type,id,title,owner type,owner,stride,likelihood,impact,risk,status,source')
    expect(lines).toContain(
      'threat,KS-01,Key extraction,element,gateway.keyStore,information-disclosure spoofing,low,critical,medium,open,Fuse Programming; Questions',
    )
    expect(lines).toContain(
      'threat,KS-09,"Key material, ""persisted""",element,gateway.keyStore,tampering,,,high,accepted,',
    )
    expect(lines).toContain(
      'threat,DF-01,DoS on CMP,relationship,gateway -> pki,denial-of-service,medium,medium,medium,open,',
    )
  })
})
