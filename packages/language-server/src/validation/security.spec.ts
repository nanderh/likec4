import { describe, expect, it } from 'vitest'
import { createTestServices } from '../test'
import { editDistance, nearestRelations } from './relation'

const spec = `
  specification {
    element system
    element component
  }
`

describe('security validation', () => {
  it('warns when the same threat id is defined on another element or relationship', async () => {
    const { addDocument, validateAll } = createTestServices()
    await addDocument(`
      ${spec}
      model {
        gateway = system {
          vault = component {
            threat SV-01 'Key extraction' { stride I }
          }
        }
        pki = system
        gateway -> pki 'CMP' {
          threat DF-01 { stride D }
        }
      }
    `)
    await addDocument(`
      model {
        extend pki {
          threat SV-01 'Copy-paste' { stride I }
          vulnerability SV-01
        }
        extend gateway -> pki 'CMP' {
          threat DF-02 { stride T }
        }
        extend gateway {
          threat DF-01 { stride D }
        }
      }
    `)
    const { errors, warnings } = await validateAll()
    expect(errors).toEqual([])
    expect(warnings.sort()).toEqual([
      `Threat id "DF-01" is also defined on gateway -> pki 'CMP'; ids should be unique in the project`,
      `Threat id "DF-01" is also defined on gateway; ids should be unique in the project`,
      `Threat id "SV-01" is also defined on gateway.vault; ids should be unique in the project`,
      `Threat id "SV-01" is also defined on pki; ids should be unique in the project`,
    ])
  })

  it('warns when an extend defines an id again for the same element', async () => {
    const { addDocument, validateAll } = createTestServices()
    await addDocument(`
      ${spec}
      model {
        gateway = system {
          threat GW-01 'Original' { stride S }
        }
      }
    `)
    await addDocument(`
      model {
        extend gateway {
          threat GW-01 'Again' { stride S }
          threat GW-02 'New' { stride T }
        }
      }
    `)
    const { errors, warnings } = await validateAll()
    expect(errors).toEqual([])
    expect(warnings).toEqual([
      'Threat id "GW-01" is defined more than once for gateway (also in an extend), only the first definition is used',
      'Threat id "GW-01" is defined more than once for gateway (also in an extend), only the first definition is used',
    ])
  })

  it('does not warn for unique ids', async () => {
    const { addDocument, validateAll } = createTestServices()
    await addDocument(`
      ${spec}
      model {
        gateway = system {
          threat GW-01 { stride S }
        }
        extend gateway {
          threat GW-02 { stride T }
        }
      }
    `)
    const { errors, warnings } = await validateAll()
    expect(errors).toEqual([])
    expect(warnings).toEqual([])
  })
})

describe('extend relation without match', () => {
  it('lists the nearest relations', async () => {
    const { addDocument, validateAll } = createTestServices()
    await addDocument(`
      ${spec}
      model {
        gateway = system
        pki = system
        meter = system
        gateway -> pki 'CMP'
        gateway -> pki 'Validates certificates'
        gateway -> meter 'Staples OCSP responses'
      }
    `)
    await addDocument(`
      model {
        extend gateway -> pki 'CMPv2' {
          threat DF-01 { stride D }
        }
        extend gateway -> meter 'Staples OSCP response' {
          threat DF-02 { stride T }
        }
        extend meter -> gateway 'Unknown' {
          threat DF-03 { stride T }
        }
      }
    `)
    const { warnings } = await validateAll()
    const prefix = 'This extend does not match any relation (by source, kind, target, title, and directionality)'
    expect(warnings).toEqual([
      `${prefix}. Nearest: gateway -> pki 'CMP', gateway -> pki 'Validates certificates'`,
      `${prefix}. Nearest: gateway -> meter 'Staples OCSP responses'`,
      `${prefix}. Nearest: gateway -> meter 'Staples OCSP responses'`,
    ])
  })

  it('editDistance and nearestRelations', () => {
    expect(editDistance('CMP', 'cmp')).toBe(0)
    expect(editDistance('Sends data to', 'Send data')).toBe(4)
    const relations = [
      { source: 'a', target: 'b', title: 'Reads', kind: 'default', isBidirectional: false },
      { source: 'a', target: 'c', title: 'Writes', kind: 'default', isBidirectional: false },
      { source: 'd', target: 'e', title: 'Writes', kind: 'default', isBidirectional: false },
    ]
    // no relation between a and c with that title: same endpoints first
    expect(nearestRelations(relations, { source: 'a', target: 'c', title: 'Write' }).map(r => r.title)).toEqual([
      'Writes',
    ])
    // no relation between a and x: relations from a, by title
    expect(nearestRelations(relations, { source: 'a', target: 'x', title: 'Write' }).map(r => r.target)).toEqual([
      'c',
      'b',
    ])
    expect(nearestRelations(relations, { source: 'x', target: 'y', title: 'Write' })).toEqual([])
  })
})
