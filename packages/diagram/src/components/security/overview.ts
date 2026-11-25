import type { LikeC4ViewModel } from '@likec4/core/model'
import {
  type Fqn,
  type RiskLevel,
  type SecuritySeverity,
  type SecurityStatus,
  type SecurityStatusGroup,
  type StrideCategory,
  compareSeverity,
  highestSeverity,
  SecuritySeverities,
  SecurityStatuses,
  securityStatusGroup,
  StrideCategories,
} from '@likec4/core/types'
import type { RegisterFilters, RegisterOwner, RegisterRow } from './register'

export type StatusGroupTally = Record<SecurityStatusGroup, number>

function emptyGroupCounts(): StatusGroupTally {
  return { unresolved: 0, carried: 0, closed: 0 }
}

/**
 * Statuses of the groups, e.g. to filter the register by a group
 */
export function statusesOfGroups(...groups: SecurityStatusGroup[]): SecurityStatus[] {
  return SecurityStatuses.filter(s => groups.includes(securityStatusGroup(s)))
}

/**
 * Statuses of items whose risk is not gone (unresolved and carried)
 */
export const NotClosedStatuses: ReadonlyArray<SecurityStatus> = statusesOfGroups('unresolved', 'carried')

/**
 * Number of rows per status group
 */
export function countStatusGroups(rows: ReadonlyArray<RegisterRow>): StatusGroupTally {
  const counts = emptyGroupCounts()
  for (const row of rows) {
    counts[row.statusGroup]++
  }
  return counts
}

export type RiskMatrixKey = `${RiskLevel}:${RiskLevel}`

export function riskMatrixKey(likelihood: RiskLevel, impact: RiskLevel): RiskMatrixKey {
  return `${likelihood}:${impact}`
}

export interface RiskMatrixCounts {
  /**
   * Threats with likelihood and impact, by `likelihood:impact`
   */
  readonly cells: Partial<Record<RiskMatrixKey, number>>
  /**
   * Threats with a risk level, but without likelihood or impact
   */
  readonly riskOnly: number
  /**
   * Threats without likelihood, impact and risk
   */
  readonly unrated: number
}

/**
 * Places threats that are not closed on the likelihood × impact matrix
 */
export function countRiskMatrix(rows: ReadonlyArray<RegisterRow>): RiskMatrixCounts {
  const cells: Partial<Record<RiskMatrixKey, number>> = {}
  let riskOnly = 0
  let unrated = 0
  for (const row of rows) {
    if (row.kind !== 'threat' || row.statusGroup === 'closed') {
      continue
    }
    if (row.likelihood && row.impact) {
      const key = riskMatrixKey(row.likelihood, row.impact)
      cells[key] = (cells[key] ?? 0) + 1
    } else if (row.risk) {
      riskOnly++
    } else {
      unrated++
    }
  }
  return { cells, riskOnly, unrated }
}

/**
 * Number of threats per STRIDE category and status group (a threat may count in several categories)
 */
export function countStride(rows: ReadonlyArray<RegisterRow>): Record<StrideCategory, StatusGroupTally> {
  const counts = Object.fromEntries(StrideCategories.map(c => [c, emptyGroupCounts()])) as Record<
    StrideCategory,
    StatusGroupTally
  >
  for (const row of rows) {
    for (const category of row.stride) {
      counts[category][row.statusGroup]++
    }
  }
  return counts
}

export type RiskBucket = SecuritySeverity | 'none'

export const RiskBuckets: ReadonlyArray<RiskBucket> = [...SecuritySeverities, 'none']

/**
 * Number of items that are not closed, per risk (threats) or severity (vulnerabilities)
 */
export function countRisk(rows: ReadonlyArray<RegisterRow>): Record<RiskBucket, number> {
  const counts = Object.fromEntries(RiskBuckets.map(b => [b, 0])) as Record<RiskBucket, number>
  for (const row of rows) {
    if (row.statusGroup !== 'closed') {
      counts[row.risk ?? 'none']++
    }
  }
  return counts
}

export interface OwnerSummary {
  readonly owner: RegisterOwner
  readonly counts: StatusGroupTally
  /**
   * Highest risk of the items that are not closed
   */
  readonly highestRisk: SecuritySeverity | null
}

function ownerKey(owner: RegisterOwner): string {
  return owner.type === 'element' ? `e:${owner.fqn}` : `r:${owner.id}`
}

/**
 * Elements and relationships with the most items that are not closed,
 * ties broken by the highest risk
 */
export function topOwners(rows: ReadonlyArray<RegisterRow>, limit: number): OwnerSummary[] {
  const byOwner = new Map<string, { owner: RegisterOwner; counts: StatusGroupTally; risks: RegisterRow['risk'][] }>()
  for (const row of rows) {
    const key = ownerKey(row.owner)
    let entry = byOwner.get(key)
    if (!entry) {
      entry = { owner: row.owner, counts: emptyGroupCounts(), risks: [] }
      byOwner.set(key, entry)
    }
    entry.counts[row.statusGroup]++
    if (row.statusGroup !== 'closed') {
      entry.risks.push(row.risk)
    }
  }
  const notClosed = (c: StatusGroupTally) => c.unresolved + c.carried
  return [...byOwner.values()]
    .map(({ owner, counts, risks }) => ({ owner, counts, highestRisk: highestSeverity(risks) }))
    .filter(o => notClosed(o.counts) > 0)
    .sort((a, b) =>
      notClosed(b.counts) - notClosed(a.counts)
      || compareSeverity(a.highestRisk, b.highestRisk)
      || a.owner.label.localeCompare(b.owner.label)
    )
    .slice(0, limit)
}

/**
 * Filters that select the rows of an owner
 */
export function ownerFilters(owner: RegisterOwner): RegisterFilters {
  return { owner: owner.label }
}

/**
 * Picks the view to show an item of the register in:
 * the current view if it is one of them, then a view of the scope element, then any element view, then the first
 */
export function pickRegisterView(
  views: Iterable<LikeC4ViewModel>,
  { currentViewId, scope }: { currentViewId?: string | undefined; scope?: Fqn | undefined } = {},
): LikeC4ViewModel | null {
  let first: LikeC4ViewModel | null = null
  let scoped: LikeC4ViewModel | null = null
  let firstElementView: LikeC4ViewModel | null = null
  for (const view of views) {
    if (view.id === currentViewId) {
      return view
    }
    first ??= view
    if (view._type === 'element') {
      firstElementView ??= view
      if (scope && view.viewOf?.id === scope) {
        scoped ??= view
      }
    }
  }
  return scoped ?? firstElementView ?? first
}
