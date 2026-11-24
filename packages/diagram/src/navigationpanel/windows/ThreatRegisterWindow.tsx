import type { LikeC4Model, LikeC4ViewModel } from '@likec4/core/model'
import {
  type StrideCategory,
  RiskLevels,
  SecuritySeverities,
  SecurityStatuses,
  StrideCategories,
  StrideLetters,
  StrideTitles,
} from '@likec4/core/types'
import { css, cx } from '@likec4/styles/css'
import { HStack, VStack } from '@likec4/styles/jsx'
import {
  ActionIcon,
  Button,
  Checkbox,
  Popover,
  ScrollArea,
  Table,
  Text,
  TextInput,
  Tooltip,
  UnstyledButton,
} from '@mantine/core'
import {
  IconAlertTriangle,
  IconArrowRight,
  IconArrowsSort,
  IconBug,
  IconCube,
  IconDownload,
  IconFilter,
  IconFilterOff,
  IconId,
  IconSortAscending,
  IconSortDescending,
} from '@tabler/icons-react'
import { type ReactNode, useMemo, useState } from 'react'
import {
  type RegisterColumn,
  type RegisterFilters,
  type RegisterRow,
  type RegisterSort,
  buildSecurityRegister,
  filterRegister,
  registerToCsv,
  SeverityBadge,
  sortRegister,
  StatusBadge,
} from '../../components/security'
import { useDiagram } from '../../hooks/useDiagram'
import { useLikeC4Model } from '../../hooks/useLikeC4Model'
import { ELEMENT_DETAILS_TAB_KEY } from '../../overlays/element-details/subject'

const table = css({
  fontSize: 'xs',
  '& th': {
    whiteSpace: 'nowrap',
    verticalAlign: 'middle',
  },
  '& td': {
    verticalAlign: 'top',
    whiteSpace: 'nowrap',
  },
  // Badges measure bold uppercase labels a few pixels short and truncate them
  '& .mantine-Badge-root': {
    width: 'max-content',
    overflow: 'visible',
  },
  '& .mantine-Badge-label': {
    overflow: 'visible',
  },
  // only title and owner wrap, other columns keep their width
  '& td[data-wrap]': {
    whiteSpace: 'normal',
    minWidth: '[160px]',
    maxWidth: '[320px]',
  },
})

const row = css({
  cursor: 'pointer',
  _hover: {
    backgroundColor: 'surface.hover',
  },
  '&[data-selected="true"]': {
    backgroundColor: '[var(--mantine-primary-color-light)]',
  },
  '&[data-status-group="closed"]': {
    opacity: '0.6',
  },
})

const mono = css({
  fontFamily: 'mono',
  fontWeight: 'semibold',
  whiteSpace: 'nowrap',
})

const strideLetter = css({
  fontFamily: 'mono',
  fontWeight: 'bold',
  opacity: '0.25',
  '&[data-active="true"]': {
    opacity: '1',
    color: '[var(--mantine-color-violet-filled)]',
  },
})

/**
 * S T R I D E letters without tooltips, cheap to render in many rows
 */
function StrideLettersCompact({ stride }: { stride: readonly StrideCategory[] }) {
  if (stride.length === 0) {
    return null
  }
  return (
    <span aria-label={stride.map(s => StrideTitles[s]).join(', ')}>
      {StrideCategories.map(c => (
        <span key={c} className={strideLetter} data-active={stride.includes(c)}>{StrideLetters[c]}</span>
      ))}
    </span>
  )
}

type Option = { value: string; label: string }

const kindOptions: Option[] = [
  { value: 'threat', label: 'Threat' },
  { value: 'vulnerability', label: 'Vulnerability' },
]
const strideOptions: Option[] = StrideCategories.map(c => ({
  value: c,
  label: `${StrideLetters[c]} — ${StrideTitles[c]}`,
}))
const levelOptions: Option[] = [
  ...RiskLevels.map(l => ({ value: l, label: l })),
  { value: 'none', label: 'not set' },
]
const riskOptions: Option[] = [
  ...SecuritySeverities.map(s => ({ value: s, label: s === 'info' ? 'info (vulnerabilities)' : s })),
  { value: 'none', label: 'not set' },
]
const statusOptions: Option[] = SecurityStatuses.map(s => ({ value: s, label: s }))

type TextColumn = 'id' | 'title' | 'owner' | 'source'
type ValuesColumn = Exclude<keyof RegisterFilters, TextColumn>

function hasValue(filters: RegisterFilters, column: keyof RegisterFilters): boolean {
  const value = filters[column]
  return typeof value === 'string' ? value.trim() !== '' : !!value && value.length > 0
}

function ColumnHeader({
  column,
  label,
  sort,
  onSort,
  filter,
  filterActive,
}: {
  column: RegisterColumn
  label: string
  sort: RegisterSort
  onSort: (column: RegisterColumn) => void
  filter: ReactNode
  filterActive: boolean
}) {
  const sorted = sort.column === column
  const SortIcon = !sorted ? IconArrowsSort : sort.direction === 'asc' ? IconSortAscending : IconSortDescending
  return (
    <Table.Th>
      <HStack gap="1" flexWrap="nowrap">
        <UnstyledButton
          fz="xs"
          fw={600}
          onClick={() => onSort(column)}
          aria-label={`Sort by ${label}`}
          className={css({ display: 'inline-flex', alignItems: 'center', gap: '1' })}>
          {label}
          <SortIcon size={12} opacity={sorted ? 1 : 0.35} />
        </UnstyledButton>
        <Popover withinPortal={false} position="bottom-start" shadow="md" trapFocus>
          <Popover.Target>
            <ActionIcon
              size="xs"
              variant={filterActive ? 'filled' : 'subtle'}
              {...(!filterActive && { color: 'gray' })}
              aria-label={`Filter ${label}`}>
              <IconFilter size={11} />
            </ActionIcon>
          </Popover.Target>
          <Popover.Dropdown p="xs">{filter}</Popover.Dropdown>
        </Popover>
      </HStack>
    </Table.Th>
  )
}

function TextFilter({ value, onChange, label }: { value: string; onChange: (value: string) => void; label: string }) {
  return (
    <TextInput
      size="xs"
      w={200}
      data-autofocus
      placeholder={`Filter ${label}...`}
      value={value}
      onChange={e => onChange(e.currentTarget.value)}
    />
  )
}

function ValuesFilter({
  options,
  value,
  onChange,
}: {
  options: ReadonlyArray<Option>
  value: ReadonlyArray<string>
  onChange: (value: string[]) => void
}) {
  return (
    <Checkbox.Group value={[...value]} onChange={onChange}>
      <VStack gap="1" alignItems="start">
        {options.map(o => <Checkbox key={o.value} size="xs" value={o.value} label={o.label} />)}
      </VStack>
    </Checkbox.Group>
  )
}

/**
 * Views that include the element, the current view first, then element views
 */
function pickView(
  views: Iterable<LikeC4ViewModel>,
  currentViewId: string,
): LikeC4ViewModel | null {
  let first: LikeC4ViewModel | null = null
  let firstElementView: LikeC4ViewModel | null = null
  for (const view of views) {
    if (view.id === currentViewId) {
      return view
    }
    first ??= view
    if (view._type === 'element') {
      firstElementView ??= view
    }
  }
  return firstElementView ?? first
}

function downloadCsv(rows: ReadonlyArray<RegisterRow>, model: LikeC4Model) {
  // BOM, so spreadsheet tools read the file as UTF-8
  const blob = new Blob(['﻿' + registerToCsv(rows)], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `threat-register-${model.projectId}.csv`
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

/**
 * All threats and vulnerabilities of the project in one table:
 * sort and filter by column, open the element or relationship in a view, export to CSV.
 */
export function ThreatRegisterWindow() {
  const model = useLikeC4Model()
  const diagram = useDiagram()
  const allRows = useMemo(() => buildSecurityRegister(model), [model])
  const [sort, setSort] = useState<RegisterSort>({ column: 'risk', direction: 'desc' })
  const [filters, setFilters] = useState<RegisterFilters>({})
  const [selected, setSelected] = useState<string | null>(null)

  const rows = useMemo(() => sortRegister(filterRegister(allRows, filters), sort), [allRows, filters, sort])
  const filtersActive = Object.keys(filters).some(k => hasValue(filters, k as keyof RegisterFilters))

  const onSort = (column: RegisterColumn) => {
    setSort(s =>
      s.column === column
        ? { column, direction: s.direction === 'asc' ? 'desc' : 'asc' }
        // levels and risk start with the highest, text columns from A
        : { column, direction: ['likelihood', 'impact', 'risk', 'stride'].includes(column) ? 'desc' : 'asc' }
    )
  }

  const setText = (column: TextColumn) => (value: string) => setFilters(f => ({ ...f, [column]: value }))
  const setValues = (column: ValuesColumn) => (value: string[]) => setFilters(f => ({ ...f, [column]: value }))

  const header = (column: RegisterColumn, label: string, filter: ReactNode) => (
    <ColumnHeader
      key={column}
      column={column}
      label={label}
      sort={sort}
      onSort={onSort}
      filter={filter}
      filterActive={hasValue(filters, column)}
    />
  )
  const textHeader = (column: TextColumn, label: string) =>
    header(
      column,
      label,
      <TextFilter label={label.toLowerCase()} value={filters[column] ?? ''} onChange={setText(column)} />,
    )
  const valuesHeader = (column: ValuesColumn, label: string, options: Option[]) =>
    header(column, label, <ValuesFilter options={options} value={filters[column] ?? []} onChange={setValues(column)} />)

  const showInView = (row: RegisterRow) => {
    setSelected(row.key)
    const currentViewId = diagram.currentView.id
    const owner = row.owner
    if (owner.type === 'element') {
      const element = model.findElement(owner.fqn)
      const view = element ? pickView(element.views(), currentViewId) : null
      if (!view) {
        openDetails(row)
      } else if (view.id === currentViewId) {
        diagram.focusOnElement(owner.fqn)
      } else {
        diagram.navigateTo(view.id, undefined, owner.fqn)
      }
      return
    }
    const relationship = model.findRelationship(owner.id, 'model')
    const view = relationship ? pickView(relationship.views(), currentViewId) : null
    if (!view || view.id === currentViewId) {
      diagram.openRelationshipDetails(owner.source, owner.target)
    } else {
      // focus on the source, the relationship starts there
      diagram.navigateTo(view.id, undefined, owner.source)
    }
  }

  const openDetails = (row: RegisterRow) => {
    setSelected(row.key)
    const owner = row.owner
    if (owner.type === 'relationship') {
      diagram.openRelationshipDetails(owner.source, owner.target)
      return
    }
    try {
      // Open details on the tab of the item (stored by useSessionStorage in ElementDetailsCard)
      sessionStorage.setItem(
        ELEMENT_DETAILS_TAB_KEY,
        JSON.stringify(row.kind === 'threat' ? 'Threats' : 'Vulnerabilities'),
      )
    } catch {
      // ignore, details open on the last active tab
    }
    diagram.openNodeDetails({ type: 'element', element: owner.fqn })
  }

  return (
    <>
      <HStack p="1" gap="sm" justify="space-between" className="drag-handle" style={{ flex: '0' }}>
        <HStack gap="sm" alignItems="baseline">
          <Text fw={600} fz="sm">Threat register</Text>
          <Text fz="xs" c="dimmed">
            {rows.length === allRows.length ? `${allRows.length} items` : `${rows.length} of ${allRows.length} items`}
          </Text>
        </HStack>
        <HStack gap="xs" pr="6">
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
            onClick={() => downloadCsv(rows, model)}>
            Export CSV
          </Button>
        </HStack>
      </HStack>
      <ScrollArea style={{ flex: 1 }} scrollbars="xy" type="auto" overscrollBehavior="contain">
        <Table className={cx(table, 'nodrag')} stickyHeader highlightOnHover={false} verticalSpacing={4}>
          <Table.Thead>
            <Table.Tr>
              {valuesHeader('kind', 'Type', kindOptions)}
              {textHeader('id', 'ID')}
              {textHeader('title', 'Title')}
              {textHeader('owner', 'Element / relationship')}
              {valuesHeader('stride', 'STRIDE', strideOptions)}
              {valuesHeader('likelihood', 'Likelihood', levelOptions)}
              {valuesHeader('impact', 'Impact', levelOptions)}
              {valuesHeader('risk', 'Risk', riskOptions)}
              {valuesHeader('status', 'Status', statusOptions)}
              {textHeader('source', 'Source')}
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rows.map(r => (
              <Table.Tr
                key={r.key}
                className={row}
                data-selected={selected === r.key}
                data-status-group={r.statusGroup}
                onClick={() => showInView(r)}>
                <Table.Td>
                  <Tooltip label={r.kind} fz="xs" withinPortal={false} openDelay={400}>
                    {r.kind === 'threat' ? <IconAlertTriangle size={14} /> : <IconBug size={14} />}
                  </Tooltip>
                </Table.Td>
                <Table.Td className={mono}>{r.id}</Table.Td>
                <Table.Td data-wrap>{r.title}</Table.Td>
                <Table.Td data-wrap>
                  <HStack gap="1" alignItems="start" flexWrap="nowrap">
                    {r.owner.type === 'element'
                      ? <IconCube size={12} style={{ flexShrink: 0, marginTop: 2 }} />
                      : <IconArrowRight size={12} style={{ flexShrink: 0, marginTop: 2 }} />}
                    <span>{r.owner.label}</span>
                  </HStack>
                </Table.Td>
                <Table.Td>
                  <StrideLettersCompact stride={r.stride} />
                </Table.Td>
                <Table.Td>{r.likelihood}</Table.Td>
                <Table.Td>{r.impact}</Table.Td>
                <Table.Td>{r.risk && <SeverityBadge severity={r.risk} />}</Table.Td>
                <Table.Td>
                  <StatusBadge status={r.status} />
                </Table.Td>
                <Table.Td data-wrap>{r.source.join(', ')}</Table.Td>
                <Table.Td>
                  <Tooltip label="Open details" fz="xs" withinPortal={false} openDelay={300}>
                    <ActionIcon
                      size="xs"
                      variant="subtle"
                      color="gray"
                      aria-label="Open details"
                      onClick={e => {
                        e.stopPropagation()
                        openDetails(r)
                      }}>
                      <IconId size={14} />
                    </ActionIcon>
                  </Tooltip>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        {rows.length === 0 && (
          <Text fz="sm" c="dimmed" ta="center" py="xl">
            No items match the filters
          </Text>
        )}
      </ScrollArea>
    </>
  )
}
