import {
  type RiskLevel,
  type StrideCategory,
  riskScore,
  StrideCategories,
  StrideLetters,
  StrideTitles,
} from '@likec4/core/types'
import { css } from '@likec4/styles/css'
import { HStack, styled, VStack } from '@likec4/styles/jsx'
import { Badge, Paper, Text, Tooltip, UnstyledButton } from '@mantine/core'
import { IconArrowRight, IconCube } from '@tabler/icons-react'
import { type ReactNode, useMemo } from 'react'
import {
  type RegisterFilters,
  type RegisterRow,
  type RiskBucket,
  type StatusGroupTally,
  countRisk,
  countRiskMatrix,
  countStride,
  NotClosedStatuses,
  ownerFilters,
  riskMatrixKey,
  riskScoreLevel,
  SecurityPalette,
  SeverityBadge,
  topOwners,
} from '../components/security'

/**
 * Colors of the status groups in bars and legends
 */
const groupColor = {
  unresolved: SecurityPalette['likec4-security-high'],
  carried: SecurityPalette['likec4-security-carried'],
  closed: SecurityPalette['likec4-security-closed'],
} as const satisfies Record<keyof StatusGroupTally, string>

const groupLabel = {
  unresolved: 'unresolved',
  carried: 'risk carried',
  closed: 'closed',
} as const satisfies Record<keyof StatusGroupTally, string>

const PanelTitle = styled('h3', {
  base: {
    margin: '0',
    fontSize: 'sm',
    fontWeight: 'semibold',
    color: 'text',
  },
})

function Panel({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  return (
    <Paper withBorder radius="md" p="md" className={css({ minWidth: '0' })}>
      <VStack gap="3" alignItems="stretch">
        <div>
          <PanelTitle>{title}</PanelTitle>
          <Text fz="xs" c="dimmed">{description}</Text>
        </div>
        {children}
      </VStack>
    </Paper>
  )
}

const listButton = css({
  display: 'grid',
  alignItems: 'center',
  gap: '2',
  width: '100%',
  paddingX: '1.5',
  paddingY: '1',
  borderRadius: 'sm',
  fontSize: 'xs',
  _hover: {
    backgroundColor: 'surface.hover',
  },
  _disabled: {
    cursor: 'default',
    opacity: '0.5',
    _hover: {
      backgroundColor: 'transparent',
    },
  },
})

const barTrack = css({
  display: 'flex',
  height: '[10px]',
  borderRadius: '[3px]',
  overflow: 'hidden',
  backgroundColor: '[var(--mantine-color-default-border)]',
})

const count = css({
  fontVariantNumeric: 'tabular-nums',
  fontWeight: 'semibold',
  textAlign: 'right',
})

const swatch = css({
  display: 'inline-block',
  width: '[10px]',
  height: '[10px]',
  borderRadius: '[2px]',
  flexShrink: 0,
})

// rows from high to low likelihood, columns from low to high impact
const likelihoodRows = ['critical', 'high', 'medium', 'low'] as const satisfies ReadonlyArray<RiskLevel>
const impactColumns = ['low', 'medium', 'high', 'critical'] as const satisfies ReadonlyArray<RiskLevel>

const matrix = css({
  display: 'grid',
  gridTemplateColumns: 'max-content repeat(4, minmax(36px, 56px))',
  gap: '1',
  alignItems: 'center',
  fontSize: 'xs',
})

const matrixCell = css({
  height: '[36px]',
  borderRadius: 'sm',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  fontWeight: 'bold',
  fontSize: 'sm',
  color: 'white',
  fontVariantNumeric: 'tabular-nums',
  transition: '[transform 100ms ease]',
  _hover: {
    transform: 'scale(1.06)',
  },
  '&[data-empty="true"]': {
    opacity: '[0.18]',
    cursor: 'default',
    _hover: {
      transform: 'none',
    },
  },
})

const axisLabel = css({
  color: 'text.dimmed',
  fontSize: 'xxs',
  textAlign: 'center',
  textTransform: 'uppercase',
  letterSpacing: 'caps.sm',
})

type OnFilter = (filters: RegisterFilters) => void

/**
 * Threats that are not closed on the likelihood × impact matrix, a cell selects its threats
 */
export function RiskMatrixPanel({ rows, onFilter }: { rows: ReadonlyArray<RegisterRow>; onFilter: OnFilter }) {
  const counts = useMemo(() => countRiskMatrix(rows), [rows])
  return (
    <Panel title="Risk matrix" description="Threats not closed, likelihood × impact">
      <div>
        <div className={matrix} role="table" aria-label="Risk matrix: likelihood by impact">
          {likelihoodRows.map(likelihood => (
            <div key={likelihood} role="row" style={{ display: 'contents' }}>
              <Text fz="xs" c="dimmed" pr={6} role="rowheader">{likelihood}</Text>
              {impactColumns.map(impact => {
                const n = counts.cells[riskMatrixKey(likelihood, impact)] ?? 0
                const score = riskScore(likelihood, impact)
                return (
                  <Tooltip
                    key={impact}
                    fz="xs"
                    label={`${n} threat${n === 1 ? '' : 's'}: likelihood ${likelihood} × impact ${impact} = ${score}`}>
                    <UnstyledButton
                      role="cell"
                      className={matrixCell}
                      data-empty={n === 0}
                      disabled={n === 0}
                      style={{ background: SecurityPalette[`likec4-security-${riskScoreLevel(score)}`] }}
                      onClick={() =>
                        onFilter({
                          kind: ['threat'],
                          likelihood: [likelihood],
                          impact: [impact],
                          status: NotClosedStatuses,
                        })}>
                      {n > 0 ? n : ''}
                    </UnstyledButton>
                  </Tooltip>
                )
              })}
            </div>
          ))}
          <span />
          {impactColumns.map(impact => <span key={impact} className={axisLabel}>{impact}</span>)}
        </div>
        <HStack justify="space-between" mt="2" gap="2" flexWrap="wrap">
          <Text fz="xxs" c="dimmed" tt="uppercase" style={{ letterSpacing: '0.04em' }}>
            rows: likelihood · columns: impact
          </Text>
        </HStack>
        {(counts.riskOnly > 0 || counts.unrated > 0) && (
          <Text fz="xs" c="dimmed" mt="1">
            Not on the matrix: {[
              counts.riskOnly > 0 && `${counts.riskOnly} with a risk level only`,
              counts.unrated > 0 && `${counts.unrated} not rated`,
            ].filter(Boolean).join(', ')}
          </Text>
        )}
      </div>
    </Panel>
  )
}

const riskLabel = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
  none: 'not rated',
} as const satisfies Record<RiskBucket, string>

const riskBarColor = {
  critical: SecurityPalette['likec4-security-critical'],
  high: SecurityPalette['likec4-security-high'],
  medium: SecurityPalette['likec4-security-medium'],
  low: SecurityPalette['likec4-security-low'],
  info: SecurityPalette['likec4-security-info'],
  none: 'var(--mantine-color-gray-5)',
} as const satisfies Record<RiskBucket, string>

/**
 * Items that are not closed by risk (threats) or severity (vulnerabilities)
 */
export function RiskPanel({ rows, onFilter }: { rows: ReadonlyArray<RegisterRow>; onFilter: OnFilter }) {
  const counts = useMemo(() => countRisk(rows), [rows])
  const buckets = (['critical', 'high', 'medium', 'low', 'info', 'none'] as const).filter(b =>
    // info is used by vulnerabilities only
    (b !== 'info' && b !== 'none') || counts[b] > 0
  )
  const max = Math.max(1, ...buckets.map(b => counts[b]))
  return (
    <Panel title="By risk" description="Threats and vulnerabilities not closed">
      <VStack gap="0.5" alignItems="stretch">
        {buckets.map(bucket => (
          <UnstyledButton
            key={bucket}
            className={listButton}
            style={{ gridTemplateColumns: '72px 1fr 36px' }}
            disabled={counts[bucket] === 0}
            onClick={() => onFilter({ risk: [bucket], status: NotClosedStatuses })}>
            <span>{riskLabel[bucket]}</span>
            <span className={barTrack}>
              <span style={{ width: `${(counts[bucket] / max) * 100}%`, background: riskBarColor[bucket] }} />
            </span>
            <span className={count}>{counts[bucket]}</span>
          </UnstyledButton>
        ))}
      </VStack>
    </Panel>
  )
}

function GroupBar({ counts, max }: { counts: StatusGroupTally; max: number }) {
  return (
    <span className={barTrack}>
      {(['unresolved', 'carried', 'closed'] as const).map(group =>
        counts[group] > 0 && (
          <span
            key={group}
            style={{ width: `${(counts[group] / max) * 100}%`, background: groupColor[group] }}
          />
        )
      )}
    </span>
  )
}

function GroupLegend() {
  return (
    <HStack gap="3" flexWrap="wrap">
      {(['unresolved', 'carried', 'closed'] as const).map(group => (
        <HStack key={group} gap="1">
          <span className={swatch} style={{ background: groupColor[group] }} />
          <Text fz="xs" c="dimmed">{groupLabel[group]}</Text>
        </HStack>
      ))}
    </HStack>
  )
}

const total = (c: StatusGroupTally) => c.unresolved + c.carried + c.closed

function groupTooltip(c: StatusGroupTally): string {
  return `${c.unresolved} unresolved, ${c.carried} risk carried, ${c.closed} closed`
}

/**
 * Threats per STRIDE category, split by status group
 */
export function StridePanel({ rows, onFilter }: { rows: ReadonlyArray<RegisterRow>; onFilter: OnFilter }) {
  const counts = useMemo(() => countStride(rows), [rows])
  const max = Math.max(1, ...StrideCategories.map(c => total(counts[c])))
  return (
    <Panel title="By STRIDE category" description="A threat counts in each of its categories">
      <VStack gap="0.5" alignItems="stretch">
        {StrideCategories.map((category: StrideCategory) => (
          <Tooltip key={category} fz="xs" label={groupTooltip(counts[category])} openDelay={300}>
            <UnstyledButton
              className={listButton}
              style={{ gridTemplateColumns: '14px minmax(0, 150px) 1fr 36px' }}
              disabled={total(counts[category]) === 0}
              onClick={() =>
                onFilter({ stride: [category] })}>
              <span className={css({ fontFamily: 'mono', fontWeight: 'bold' })}>{StrideLetters[category]}</span>
              <span className={css({ truncate: true })}>{StrideTitles[category]}</span>
              <GroupBar counts={counts[category]} max={max} />
              <span className={count}>{total(counts[category])}</span>
            </UnstyledButton>
          </Tooltip>
        ))}
      </VStack>
      <GroupLegend />
    </Panel>
  )
}

/**
 * Elements and relationships with the most items that are not closed
 */
export function TopOwnersPanel({ rows, onFilter, limit = 8 }: {
  rows: ReadonlyArray<RegisterRow>
  onFilter: OnFilter
  limit?: number
}) {
  const owners = useMemo(() => topOwners(rows, limit), [rows, limit])
  const max = Math.max(1, ...owners.map(o => o.counts.unresolved + o.counts.carried))
  return (
    <Panel title="Hotspots" description="Elements and relationships with the most items not closed">
      {owners.length === 0 && <Text fz="xs" c="dimmed">Nothing open</Text>}
      <VStack gap="0.5" alignItems="stretch">
        {owners.map(({ owner, counts, highestRisk }) => (
          <Tooltip key={owner.label} fz="xs" label={groupTooltip(counts)} openDelay={300}>
            <UnstyledButton
              className={listButton}
              style={{ gridTemplateColumns: '14px minmax(0, 1fr) 40px 64px 24px' }}
              onClick={() =>
                onFilter(ownerFilters(owner))}>
              {owner.type === 'element' ? <IconCube size={12} /> : <IconArrowRight size={12} />}
              <span className={css({ truncate: true })}>{owner.label}</span>
              <GroupBar counts={{ ...counts, closed: 0 }} max={max} />
              <span className={css({ display: 'flex', justifyContent: 'flex-end' })}>
                {highestRisk
                  ? <SeverityBadge severity={highestRisk} />
                  : <Badge size="xs" variant="default">not rated</Badge>}
              </span>
              <span className={count}>{counts.unresolved + counts.carried}</span>
            </UnstyledButton>
          </Tooltip>
        ))}
      </VStack>
    </Panel>
  )
}
