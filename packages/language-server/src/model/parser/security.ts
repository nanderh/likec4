import type * as c4 from '@likec4/core'
import {
  type RiskLevel,
  type SecuritySeverity,
  type SecurityStatus,
  parseStrideCategory,
  RiskLevels,
  SecuritySeverities,
  SecurityStatuses,
  StrideCategories,
} from '@likec4/core/types'
import { isNumber, isString } from 'remeda'
import { dedent } from 'strip-indent'
import type { ast } from '../../ast'

type AttributeSpec =
  | { type: 'enum'; values: readonly string[]; parse: (value: string) => string | null; multiple?: boolean }
  | { type: 'number'; min: number; max: number }
  | { type: 'text' }
  | { type: 'markdown' }

/**
 * Normalizes enum-like values: `inProgress`, `in_progress`, `In Progress` -> `in-progress`
 */
function normalizeEnum(value: string): string {
  return value
    .trim()
    .replace(/([a-z])([A-Z])/g, '$1-$2')
    .replace(/[\s_]+/g, '-')
    .toLowerCase()
}

function enumOf<T extends string>(values: readonly T[], aliases: Record<string, T> = {}) {
  return (value: string): T | null => {
    const normalized = normalizeEnum(value)
    return values.find(v => v === normalized) ?? aliases[normalized] ?? null
  }
}

const parseSeverity = enumOf<SecuritySeverity>(SecuritySeverities, {
  informational: 'info',
  none: 'info',
  med: 'medium',
  moderate: 'medium',
})
const parseRiskLevel = enumOf<RiskLevel>(RiskLevels, {
  med: 'medium',
  moderate: 'medium',
})
const parseStatus = enumOf<SecurityStatus>(SecurityStatuses, {
  'inprogress': 'in-progress',
  'wip': 'in-progress',
  'fixed': 'resolved',
  'closed': 'resolved',
  'done': 'resolved',
  'false-positive': 'false-positive',
  'falsepositive': 'false-positive',
  'transfer': 'transferred',
  'accept': 'accepted',
  'mitigate': 'mitigated',
})

const status: AttributeSpec = { type: 'enum', values: SecurityStatuses, parse: parseStatus }
const riskLevel: AttributeSpec = { type: 'enum', values: RiskLevels, parse: parseRiskLevel }

export const vulnerabilityAttributes = {
  severity: { type: 'enum', values: SecuritySeverities, parse: parseSeverity },
  cvss: { type: 'number', min: 0, max: 10 },
  vector: { type: 'text' },
  cwe: { type: 'text' },
  status,
  mitigation: { type: 'markdown' },
} as const satisfies Record<string, AttributeSpec>

export const threatAttributes = {
  stride: {
    type: 'enum',
    values: StrideCategories,
    parse: parseStrideCategory,
    multiple: true,
  },
  likelihood: riskLevel,
  impact: riskLevel,
  risk: riskLevel,
  status,
  mitigation: { type: 'markdown' },
} as const satisfies Record<string, AttributeSpec>

export function securityAttributesOf(
  item: ast.SecurityProperty,
): Record<string, AttributeSpec> {
  return item.$type === 'ThreatProperty' ? threatAttributes : vulnerabilityAttributes
}

function rawValue(value: ast.SecurityItemValue): string {
  switch (true) {
    case isString(value.markdown):
      return value.markdown
    case isString(value.text):
      return value.text
    case isNumber(value.number):
      return value.number.toString()
    default:
      return value.id ?? ''
  }
}

type AttributeResult =
  | { value: string | number | c4.MarkdownOrString | string[]; error?: never }
  | { value?: never; error: string }

/**
 * Reads attribute value according to the spec,
 * returns an error message if the value is not valid.
 */
export function readSecurityAttribute(spec: AttributeSpec, attr: ast.SecurityItemAttribute): AttributeResult {
  if (spec.type !== 'enum' || !spec.multiple) {
    if (attr.values.length > 1) {
      return { error: `Expected single value for "${attr.key}"` }
    }
  }
  const first = attr.values[0]
  if (!first) {
    return { error: `Missing value for "${attr.key}"` }
  }
  switch (spec.type) {
    case 'enum': {
      const parsed = [] as string[]
      for (const v of attr.values) {
        const raw = rawValue(v)
        const value = spec.parse(raw)
        if (!value) {
          return { error: `Invalid value "${raw}" for "${attr.key}", expected one of: ${spec.values.join(', ')}` }
        }
        if (!parsed.includes(value)) {
          parsed.push(value)
        }
      }
      return { value: spec.multiple ? parsed : parsed[0]! }
    }
    case 'number': {
      const value = isNumber(first.number) ? first.number : parseFloat(rawValue(first))
      if (isNaN(value) || value < spec.min || value > spec.max) {
        return { error: `Invalid value for "${attr.key}", expected number between ${spec.min} and ${spec.max}` }
      }
      return { value }
    }
    case 'markdown': {
      if (isString(first.markdown)) {
        return { value: { md: dedent(first.markdown).trim() } }
      }
      return { value: { txt: dedent(rawValue(first)).trim() } }
    }
    case 'text': {
      return { value: rawValue(first).trim() }
    }
  }
}
