import type { Fqn, SecurityStatusGroup } from '@likec4/core/types'
import { css } from '@likec4/styles/css'
import { HStack, styled } from '@likec4/styles/jsx'
import { ActionIcon, Button, Paper, ScrollArea, SegmentedControl, Text, Tooltip } from '@mantine/core'
import { IconDownload, IconFilterOff, IconFocusCentered } from '@tabler/icons-react'
import { type ReactNode, useMemo, useRef, useState } from 'react'
import {
  type RegisterFilters,
  type RegisterRow,
  type RegisterSort,
  downloadRegisterCsv,
  filterRegister,
  hasActiveRegisterFilters,
  pickRegisterView,
  registerToCsv,
  SecurityRegisterTable,
  sortRegister,
  statusesOfGroups,
  ThreatCard,
  VulnerabilityCard,
} from '../components/security'
import { useLikeC4Model } from '../hooks/useLikeC4Model'
import { RiskMatrixPanel, RiskPanel, StridePanel, TopOwnersPanel } from './SummaryPanels'

export interface SecurityOverviewProps {
  /**
   * Rows of the register, see `buildSecurityRegister`
   */
  rows: ReadonlyArray<RegisterRow>
  /**
   * Called to show an element (or the source of a relationship) in a view
   */
  onShowInView: (viewId: string, focusOnElement: Fqn) => void
}

const Grid = styled('div', {
  base: {
    display: 'grid',
    gap: '4',
    gridTemplateColumns: {
      base: '1fr',
      md: 'repeat(2, minmax(0, 1fr))',
      xl: 'repeat(4, minmax(0, 1fr))',
    },
    alignItems: 'start',
  },
})

const SectionTitle = styled('h2', {
  base: {
    margin: '0',
    fontSize: 'md',
    fontWeight: 'semibold',
    color: 'text',
  },
})

type StatusQuickFilter = 'all' | 'not-closed' | SecurityStatusGroup

const quickFilters = [
  { value: 'all', label: 'All' },
  { value: 'not-closed', label: 'Not closed' },
  { value: 'unresolved', label: 'Unresolved' },
  { value: 'carried', label: 'Risk carried' },
  { value: 'closed', label: 'Closed' },
] as const satisfies ReadonlyArray<{ value: StatusQuickFilter; label: string }>

function statusesOf(quick: StatusQuickFilter): RegisterFilters['status'] {
  switch (quick) {
    case 'all':
      return undefined
    case 'not-closed':
      return statusesOfGroups('unresolved', 'carried')
    default:
      return statusesOfGroups(quick)
  }
}

/**
 * Quick filter that matches the status filter, if any
 */
function quickFilterOf(filters: RegisterFilters): StatusQuickFilter | null {
  const selected = filters.status ?? []
  if (selected.length === 0) {
    return 'all'
  }
  const same = (statuses: RegisterFilters['status']) =>
    !!statuses && statuses.length === selected.length && statuses.every(s => selected.includes(s))
  return quickFilters.find(q => q.value !== 'all' && same(statusesOf(q.value)))?.value ?? null
}

function ExpandedItem({ row }: { row: RegisterRow }) {
  return (
    <div className={css({ maxWidth: '[880px]' })}>
      {row.kind === 'threat' ? <ThreatCard threat={row.item} /> : <VulnerabilityCard vulnerability={row.item} />}
    </div>
  )
}

/**
 * Overview of all threats and vulnerabilities of the project:
 * summary panels (risk matrix, risk, STRIDE, hotspots) and the register.
 * A click on a panel filters the register, a click on a row shows the details of the item.
 */
export function SecurityOverview({ rows: allRows, onShowInView }: SecurityOverviewProps) {
  const model = useLikeC4Model()
  const [sort, setSort] = useState<RegisterSort>({ column: 'risk', direction: 'desc' })
  const [filters, setFilters] = useState<RegisterFilters>({})
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set())
  const registerRef = useRef<HTMLDivElement>(null)

  const rows = useMemo(() => sortRegister(filterRegister(allRows, filters), sort), [allRows, filters, sort])
  const filtersActive = hasActiveRegisterFilters(filters)
  const quickFilter = quickFilterOf(filters)

  const filterFromPanel = (next: RegisterFilters) => {
    setFilters(next)
    registerRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  const toggle = (row: RegisterRow) => {
    setExpanded(current => {
      const next = new Set(current)
      if (!next.delete(row.key)) {
        next.add(row.key)
      }
      return next
    })
  }

  const viewOf = (row: RegisterRow): { viewId: string; focus: Fqn } | null => {
    const owner = row.owner
    if (owner.type === 'element') {
      const view = pickRegisterView(model.findElement(owner.fqn)?.views() ?? [], { scope: owner.fqn })
      return view ? { viewId: view.id, focus: owner.fqn } : null
    }
    const view = pickRegisterView(model.findRelationship(owner.id, 'model')?.views() ?? [])
    // focus on the source, the relationship starts there
    return view ? { viewId: view.id, focus: owner.source } : null
  }

  const renderActions = (row: RegisterRow): ReactNode => {
    const target = viewOf(row)
    return (
      <Tooltip label={target ? 'Show in view' : 'Not in any view'} fz="xs" openDelay={300}>
        <ActionIcon
          size="xs"
          variant="subtle"
          color="gray"
          aria-label="Show in view"
          disabled={!target}
          onClick={e => {
            e.stopPropagation()
            if (target) {
              onShowInView(target.viewId, target.focus)
            }
          }}>
          <IconFocusCentered size={14} />
        </ActionIcon>
      </Tooltip>
    )
  }

  return (
    <>
      <Grid>
        <RiskMatrixPanel rows={allRows} onFilter={filterFromPanel} />
        <RiskPanel rows={allRows} onFilter={filterFromPanel} />
        <StridePanel rows={allRows} onFilter={filterFromPanel} />
        <TopOwnersPanel rows={allRows} onFilter={filterFromPanel} />
      </Grid>

      <Paper
        ref={registerRef}
        withBorder
        radius="md"
        mt="xl"
        className={css({ overflow: 'hidden', scrollMarginTop: '4' })}>
        <HStack px="md" py="sm" gap="md" justify="space-between" flexWrap="wrap">
          <HStack gap="sm" alignItems="baseline">
            <SectionTitle>Register</SectionTitle>
            <Text fz="xs" c="dimmed">
              {rows.length === allRows.length ? `${allRows.length} items` : `${rows.length} of ${allRows.length} items`}
            </Text>
          </HStack>
          <HStack gap="xs" flexWrap="wrap">
            <SegmentedControl
              size="xs"
              data={[...quickFilters]}
              // no item is active when the status filter is a custom selection
              value={quickFilter ?? ''}
              onChange={value => setFilters(f => ({ ...f, status: statusesOf(value || 'all') ?? [] }))}
            />
            {filtersActive && (
              <Button
                size="compact-xs"
                variant="subtle"
                color="gray"
                leftSection={<IconFilterOff size={12} />}
                onClick={() => setFilters({})}>
                Clear filters
              </Button>
            )}
            <Button
              size="compact-xs"
              variant="default"
              leftSection={<IconDownload size={12} />}
              disabled={rows.length === 0}
              onClick={() => downloadRegisterCsv(registerToCsv(rows), `threat-register-${model.projectId}.csv`)}>
              Export CSV
            </Button>
          </HStack>
        </HStack>
        <ScrollArea.Autosize mah="calc(100vh - 160px)" scrollbars="xy" type="auto" offsetScrollbars>
          <SecurityRegisterTable
            rows={rows}
            sort={sort}
            onSortChange={setSort}
            filters={filters}
            onFiltersChange={setFilters}
            onRowClick={toggle}
            renderExpanded={row => expanded.has(row.key) ? <ExpandedItem row={row} /> : null}
            renderActions={renderActions}
            withinPortal
          />
          {rows.length === 0 && (
            <Text fz="sm" c="dimmed" ta="center" py="xl">
              No items match the filters
            </Text>
          )}
        </ScrollArea.Autosize>
      </Paper>
    </>
  )
}
