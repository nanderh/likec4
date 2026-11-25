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
import { ActionIcon, Checkbox, Popover, Table, TextInput, Tooltip, UnstyledButton } from '@mantine/core'
import {
  IconAlertTriangle,
  IconArrowRight,
  IconArrowsSort,
  IconBug,
  IconCube,
  IconFilter,
  IconSortAscending,
  IconSortDescending,
} from '@tabler/icons-react'
import { type ReactNode, Fragment } from 'react'
import type { RegisterColumn, RegisterFilters, RegisterRow, RegisterSort } from './register'
import { SeverityBadge, StatusBadge } from './SecurityItems'

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
  // only title, owner and source wrap, other columns keep their width
  '& td[data-wrap]': {
    whiteSpace: 'normal',
    minWidth: '[160px]',
    maxWidth: '[320px]',
  },
  '& td[data-expanded]': {
    whiteSpace: 'normal',
    paddingBottom: '3',
  },
})

const rowClass = css({
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

/**
 * Returns true if any filter of the register is set
 */
export function hasActiveRegisterFilters(filters: RegisterFilters): boolean {
  return Object.keys(filters).some(k => hasValue(filters, k as keyof RegisterFilters))
}

/**
 * Sort after a click on the column header: toggles the direction of the sorted column,
 * levels and risk start with the highest, text columns from A
 */
export function nextRegisterSort(sort: RegisterSort, column: RegisterColumn): RegisterSort {
  if (sort.column === column) {
    return { column, direction: sort.direction === 'asc' ? 'desc' : 'asc' }
  }
  return { column, direction: ['likelihood', 'impact', 'risk', 'stride'].includes(column) ? 'desc' : 'asc' }
}

/**
 * Downloads the rows as a CSV file
 */
export function downloadRegisterCsv(csv: string, fileName: string) {
  // BOM, so spreadsheet tools read the file as UTF-8
  const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = fileName
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

function ColumnHeader({
  column,
  label,
  sort,
  onSort,
  filter,
  filterActive,
  withinPortal,
}: {
  column: RegisterColumn
  label: string
  sort: RegisterSort
  onSort: (column: RegisterColumn) => void
  filter: ReactNode
  filterActive: boolean
  withinPortal: boolean
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
        <Popover withinPortal={withinPortal} position="bottom-start" shadow="md" trapFocus>
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

const ColumnCount = 11

export interface SecurityRegisterTableProps {
  /**
   * Rows to show, already filtered and sorted
   */
  rows: ReadonlyArray<RegisterRow>
  sort: RegisterSort
  onSortChange: (sort: RegisterSort) => void
  filters: RegisterFilters
  onFiltersChange: (filters: RegisterFilters) => void
  /**
   * Key of the highlighted row
   */
  selected?: string | null | undefined
  onRowClick?: ((row: RegisterRow) => void) | undefined
  /**
   * Renders content under the row, if it returns null the row is not expanded
   */
  renderExpanded?: ((row: RegisterRow) => ReactNode) | undefined
  /**
   * Renders the last column, e.g. buttons
   */
  renderActions?: ((row: RegisterRow) => ReactNode) | undefined
  /**
   * Render filter popovers and tooltips in a portal,
   * false inside the diagram (shadow root, floating windows)
   * @default false
   */
  withinPortal?: boolean | undefined
  /**
   * Keep the header visible when the table scrolls (in the nearest scroll container)
   * @default true
   */
  stickyHeader?: boolean | undefined
  className?: string | undefined
}

/**
 * Table of threats and vulnerabilities with sortable and filterable columns.
 * Sort and filters are controlled by the parent.
 */
export function SecurityRegisterTable({
  rows,
  sort,
  onSortChange,
  filters,
  onFiltersChange,
  selected,
  onRowClick,
  renderExpanded,
  renderActions,
  withinPortal = false,
  stickyHeader = true,
  className,
}: SecurityRegisterTableProps) {
  const onSort = (column: RegisterColumn) => onSortChange(nextRegisterSort(sort, column))
  const setText = (column: TextColumn) => (value: string) => onFiltersChange({ ...filters, [column]: value })
  const setValues = (column: ValuesColumn) => (value: string[]) => onFiltersChange({ ...filters, [column]: value })

  const header = (column: RegisterColumn, label: string, filter: ReactNode) => (
    <ColumnHeader
      key={column}
      column={column}
      label={label}
      sort={sort}
      onSort={onSort}
      filter={filter}
      filterActive={hasValue(filters, column)}
      withinPortal={withinPortal}
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

  return (
    <Table className={cx(table, className)} stickyHeader={stickyHeader} highlightOnHover={false} verticalSpacing={4}>
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
        {rows.map(r => {
          const expanded = renderExpanded?.(r) ?? null
          return (
            <Fragment key={r.key}>
              <Table.Tr
                className={rowClass}
                data-selected={selected === r.key}
                data-status-group={r.statusGroup}
                aria-expanded={renderExpanded ? expanded !== null : undefined}
                onClick={() => onRowClick?.(r)}>
                <Table.Td>
                  <Tooltip label={r.kind} fz="xs" withinPortal={withinPortal} openDelay={400}>
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
                <Table.Td>{renderActions?.(r)}</Table.Td>
              </Table.Tr>
              {expanded !== null && (
                <Table.Tr>
                  <Table.Td colSpan={ColumnCount} data-expanded>{expanded}</Table.Td>
                </Table.Tr>
              )}
            </Fragment>
          )
        })}
      </Table.Tbody>
    </Table>
  )
}
