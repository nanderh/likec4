import type { LikeC4Model } from '@likec4/core/model'
import {
  type Fqn,
  type RiskLevel,
  type scalar,
  type SecuritySeverity,
  type SecurityStatus,
  type SecurityStatusGroup,
  type StrideCategory,
  type Threat,
  type Vulnerability,
  compareSeverity,
  securityStatusGroup,
  StrideCategories,
  StrideLetters,
  threatRisk,
  vulnerabilitySeverity,
} from '@likec4/core/types'

export type SecurityItemKind = 'threat' | 'vulnerability'

export type RegisterOwner =
  | {
    readonly type: 'element'
    readonly fqn: Fqn
    readonly label: string
  }
  | {
    readonly type: 'relationship'
    readonly id: scalar.RelationId
    readonly source: Fqn
    readonly target: Fqn
    readonly label: string
  }

/**
 * Row of the threat register: a threat or a vulnerability with its owner
 */
export interface RegisterRow {
  /**
   * Unique key of the row (the same item id may be defined on several owners)
   */
  readonly key: string
  readonly kind: SecurityItemKind
  readonly id: string
  readonly title: string
  readonly owner: RegisterOwner
  readonly stride: readonly StrideCategory[]
  readonly likelihood: RiskLevel | null
  readonly impact: RiskLevel | null
  /**
   * Risk of a threat, severity of a vulnerability
   */
  readonly risk: SecuritySeverity | null
  /**
   * Status, `open` if not set
   */
  readonly status: SecurityStatus
  readonly statusGroup: SecurityStatusGroup
}

export type RegisterColumn =
  | 'kind'
  | 'id'
  | 'title'
  | 'owner'
  | 'stride'
  | 'likelihood'
  | 'impact'
  | 'risk'
  | 'status'

function elementLabel(element: LikeC4Model.Element): string {
  return element.title === element.id ? element.id : `${element.title} (${element.id})`
}

function relationshipLabel(relationship: LikeC4Model.Relationship): string {
  const arrow = `${relationship.source.title} → ${relationship.target.title}`
  return relationship.title ? `${arrow}: ${relationship.title}` : arrow
}

function threatRow(threat: Threat, owner: RegisterOwner, ownerKey: string): RegisterRow {
  const status = threat.status ?? 'open'
  return {
    key: `t:${ownerKey}:${threat.id}`,
    kind: 'threat',
    id: threat.id,
    title: threat.title ?? '',
    owner,
    stride: threat.stride,
    likelihood: threat.likelihood ?? null,
    impact: threat.impact ?? null,
    risk: threatRisk(threat),
    status,
    statusGroup: securityStatusGroup(status),
  }
}

function vulnerabilityRow(vulnerability: Vulnerability, owner: RegisterOwner, ownerKey: string): RegisterRow {
  const status = vulnerability.status ?? 'open'
  return {
    key: `v:${ownerKey}:${vulnerability.id}`,
    kind: 'vulnerability',
    id: vulnerability.id,
    title: vulnerability.title ?? '',
    owner,
    stride: [],
    likelihood: null,
    impact: null,
    risk: vulnerabilitySeverity(vulnerability),
    status,
    statusGroup: securityStatusGroup(status),
  }
}

/**
 * Collects all threats and vulnerabilities of the model, of elements and relationships
 */
export function buildSecurityRegister(model: LikeC4Model): RegisterRow[] {
  const rows = [] as RegisterRow[]
  for (const element of model.elements()) {
    if (!element.hasSecurity()) {
      continue
    }
    const owner: RegisterOwner = { type: 'element', fqn: element.id, label: elementLabel(element) }
    const ownerKey = `e:${element.id}`
    rows.push(
      ...element.threats.map(t => threatRow(t, owner, ownerKey)),
      ...element.vulnerabilities.map(v => vulnerabilityRow(v, owner, ownerKey)),
    )
  }
  for (const relationship of model.relationships()) {
    if (!relationship.hasSecurity()) {
      continue
    }
    const owner: RegisterOwner = {
      type: 'relationship',
      id: relationship.id,
      source: relationship.source.id,
      target: relationship.target.id,
      label: relationshipLabel(relationship),
    }
    const ownerKey = `r:${relationship.id}`
    rows.push(
      ...relationship.threats.map(t => threatRow(t, owner, ownerKey)),
      ...relationship.vulnerabilities.map(v => vulnerabilityRow(v, owner, ownerKey)),
    )
  }
  return rows
}

const levelRank = { critical: 4, high: 3, medium: 2, low: 1 } as const satisfies Record<RiskLevel, number>
const statusRank = {
  'open': 0,
  'in-progress': 1,
  'accepted': 2,
  'transferred': 3,
  'mitigated': 4,
  'resolved': 5,
  'false-positive': 6,
} as const satisfies Record<SecurityStatus, number>

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' })

function strideKey(stride: readonly StrideCategory[]): string {
  return StrideCategories.map(c => stride.includes(c) ? StrideLetters[c] : '-').join('')
}

/**
 * Compares rows by a column, ascending.
 * Levels and severities compare from low to high, statuses in lifecycle order,
 * empty values go last.
 */
export function compareRegisterRows(a: RegisterRow, b: RegisterRow, column: RegisterColumn): number {
  switch (column) {
    case 'kind':
      return collator.compare(a.kind, b.kind)
    case 'id':
      return collator.compare(a.id, b.id)
    case 'title':
      return collator.compare(a.title, b.title)
    case 'owner':
      return collator.compare(a.owner.label, b.owner.label)
    case 'stride':
      // rows with more categories first, then by letters
      return b.stride.length - a.stride.length || collator.compare(strideKey(a.stride), strideKey(b.stride))
    case 'likelihood':
    case 'impact': {
      const av = a[column], bv = b[column]
      return (av ? levelRank[av] : Infinity) - (bv ? levelRank[bv] : Infinity)
    }
    case 'risk':
      // compareSeverity sorts high first, reversed for ascending order
      return a.risk && b.risk ? -compareSeverity(a.risk, b.risk) : (a.risk ? -1 : b.risk ? 1 : 0)
    case 'status':
      return statusRank[a.status] - statusRank[b.status]
  }
}

export interface RegisterSort {
  readonly column: RegisterColumn
  readonly direction: 'asc' | 'desc'
}

/**
 * Sorts rows by the column, rows with equal values keep their order by id
 */
export function sortRegister(rows: ReadonlyArray<RegisterRow>, sort: RegisterSort): RegisterRow[] {
  const sign = sort.direction === 'asc' ? 1 : -1
  return [...rows].sort((a, b) =>
    sign * compareRegisterRows(a, b, sort.column)
    || compareRegisterRows(a, b, 'id')
    || compareRegisterRows(a, b, 'owner')
  )
}

/**
 * Filters of the register:
 * - text columns match a case-insensitive substring
 * - enum columns match any of the selected values (empty selection matches all)
 */
export interface RegisterFilters {
  readonly id?: string
  readonly title?: string
  readonly owner?: string
  readonly kind?: ReadonlyArray<SecurityItemKind>
  /**
   * Rows with any of the selected categories
   */
  readonly stride?: ReadonlyArray<StrideCategory>
  readonly likelihood?: ReadonlyArray<RiskLevel | 'none'>
  readonly impact?: ReadonlyArray<RiskLevel | 'none'>
  readonly risk?: ReadonlyArray<SecuritySeverity | 'none'>
  readonly status?: ReadonlyArray<SecurityStatus>
}

function includesText(value: string, filter: string | undefined): boolean {
  return !filter || value.toLowerCase().includes(filter.trim().toLowerCase())
}

function includesValue<T extends string>(value: T | null, selected: ReadonlyArray<T | 'none'> | undefined): boolean {
  return !selected || selected.length === 0 || selected.includes(value ?? 'none')
}

export function filterRegister(rows: ReadonlyArray<RegisterRow>, filters: RegisterFilters): RegisterRow[] {
  return rows.filter(row =>
    includesText(row.id, filters.id)
    && includesText(row.title, filters.title)
    && includesText(row.owner.label, filters.owner)
    && includesValue(row.kind, filters.kind)
    && (!filters.stride?.length || row.stride.some(s => filters.stride!.includes(s)))
    && includesValue(row.likelihood, filters.likelihood)
    && includesValue(row.impact, filters.impact)
    && includesValue(row.risk, filters.risk)
    && includesValue(row.status, filters.status)
  )
}

function csvCell(value: string): string {
  return /[",\r\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value
}

export const RegisterCsvColumns = [
  'type',
  'id',
  'title',
  'owner type',
  'owner',
  'stride',
  'likelihood',
  'impact',
  'risk',
  'status',
] as const

/**
 * Converts rows to CSV (RFC 4180), with a header row
 */
export function registerToCsv(rows: ReadonlyArray<RegisterRow>): string {
  const lines = [RegisterCsvColumns.join(',')]
  for (const row of rows) {
    lines.push(
      [
        row.kind,
        row.id,
        row.title,
        row.owner.type,
        row.owner.type === 'element' ? row.owner.fqn : `${row.owner.source} -> ${row.owner.target}`,
        row.stride.join(' '),
        row.likelihood ?? '',
        row.impact ?? '',
        row.risk ?? '',
        row.status,
      ].map(csvCell).join(','),
    )
  }
  return lines.join('\r\n') + '\r\n'
}
