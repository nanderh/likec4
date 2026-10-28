import { describe, it } from 'vitest'
import { createTestServices } from '../../test'

describe('LikeC4ModelBuilder - vulnerabilities and threats', () => {
  it('parses vulnerabilities and threats of an element', async ({ expect }) => {
    const { validate, buildLikeC4Model } = createTestServices()
    const { errors, warnings } = await validate(`
      specification {
        element system
      }
      model {
        system gateway {
          vulnerability CVE-2024-3094 'xz backdoor' {
            severity critical
            cvss 10.0
            cwe CWE-506
            status in_progress
            description '''
              Malicious code in **xz** upstream tarballs
            '''
            link https://nvd.nist.gov/vuln/detail/CVE-2024-3094
          }
          vulnerability VULN-2 {
            title 'Outdated TLS'
            cvss 5.3
          }
          threat T-001 'Spoofed device identity' {
            stride S, tampering
            likelihood medium
            impact high
            status mitigated
            mitigation 'Mutual TLS with device certificates'
          }
        }
      }
    `)
    expect(errors).toEqual([])
    expect(warnings).toEqual([])

    const model = await buildLikeC4Model()
    const gateway = model.element('gateway')
    expect(gateway.vulnerabilities).toEqual([
      {
        id: 'CVE-2024-3094',
        title: 'xz backdoor',
        severity: 'critical',
        cvss: 10,
        cwe: 'CWE-506',
        status: 'in-progress',
        description: { md: 'Malicious code in **xz** upstream tarballs' },
        links: [{ url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-3094' }],
      },
      {
        id: 'VULN-2',
        title: 'Outdated TLS',
        cvss: 5.3,
      },
    ])
    expect(gateway.threats).toEqual([
      {
        id: 'T-001',
        title: 'Spoofed device identity',
        stride: ['spoofing', 'tampering'],
        likelihood: 'medium',
        impact: 'high',
        status: 'mitigated',
        mitigation: { txt: 'Mutual TLS with device certificates' },
      },
    ])
    expect(gateway.hasSecurity()).toBe(true)
  })

  it('parses threats of a relationship', async ({ expect }) => {
    const { validate, buildLikeC4Model } = createTestServices()
    const { errors } = await validate(`
      specification {
        element system
      }
      model {
        system a
        system b
        a -> b 'sends readings' {
          threat T-002 'Readings tampered in transit' {
            stride tampering, information-disclosure
            risk high
          }
        }
      }
    `)
    expect(errors).toEqual([])
    const model = await buildLikeC4Model()
    const [rel] = [...model.relationships()]
    expect(rel!.threats).toEqual([
      {
        id: 'T-002',
        title: 'Readings tampered in transit',
        stride: ['tampering', 'information-disclosure'],
        risk: 'high',
      },
    ])
  })

  it('merges threats from extend element and extend relation', async ({ expect }) => {
    const { validate, buildLikeC4Model } = createTestServices()
    await validate(`
      specification {
        element system
      }
      model {
        system a {
          threat T-1 {
            stride spoofing
          }
        }
        system b
        a -> b
      }
    `)
    const { errors } = await validate(`
      model {
        extend a {
          threat T-1 'duplicate is ignored' {
            stride tampering
          }
          threat T-2 {
            stride denial-of-service
          }
          vulnerability CVE-1 {
            severity low
          }
        }
        extend a -> b {
          threat T-3 {
            stride repudiation
          }
        }
      }
    `)
    expect(errors).toEqual([])
    const model = await buildLikeC4Model()
    const a = model.element('a')
    expect(a.threats.map(t => [t.id, t.stride])).toEqual([
      ['T-1', ['spoofing']],
      ['T-2', ['denial-of-service']],
    ])
    expect(a.vulnerabilities).toEqual([{ id: 'CVE-1', severity: 'low' }])
    const [rel] = [...model.relationships()]
    expect(rel!.threats).toEqual([{ id: 'T-3', stride: ['repudiation'] }])
  })

  it('reports invalid values but keeps the element', async ({ expect }) => {
    const { validate, buildLikeC4Model } = createTestServices()
    const { errors, warnings } = await validate(`
      specification {
        element system
      }
      model {
        system gateway {
          vulnerability CVE-1 {
            severity catastrophic
            cvss 11
            owner 'team'
          }
          vulnerability CVE-1
          threat T-1 {
            likelihood high
          }
        }
      }
    `)
    expect(errors).toEqual([
      'Invalid value "catastrophic" for "severity", expected one of: critical, high, medium, low, info',
      'Invalid value for "cvss", expected number between 0 and 10',
      'Vulnerability with id "CVE-1" is already defined',
    ])
    expect(warnings).toEqual([
      'Unknown property "owner", expected one of: severity, cvss, vector, cwe, status, mitigation',
      'Threat has no STRIDE category, add "stride spoofing, tampering, ..."',
    ])
    const model = await buildLikeC4Model()
    const gateway = model.element('gateway')
    expect(gateway.threats).toEqual([{ id: 'T-1', stride: [], likelihood: 'high' }])
  })

  it('does not break identifiers used as metadata keys', async ({ expect }) => {
    const { validate } = createTestServices()
    const { errors } = await validate(`
      specification {
        element system
      }
      model {
        system gateway {
          metadata {
            severity 'high'
            status 'live'
          }
        }
      }
    `)
    expect(errors).toEqual([])
  })
})
