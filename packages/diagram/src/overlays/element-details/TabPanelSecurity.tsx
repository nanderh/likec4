import type { LikeC4Model } from '@likec4/core/model'
import { Box, Divider, Stack, Text } from '@mantine/core'
import { type ReactNode, useMemo } from 'react'
import {
  type SecurityItemsSubject,
  elementSecurityScope,
  sortThreats,
  sortVulnerabilities,
  StrideSummary,
  ThreatCard,
  VulnerabilityCard,
  VulnerabilitySummary,
} from '../../components/security'

type Group<T> = {
  key: string
  label: ReactNode
  items: T[]
}

type SecurityItemsOf<T> = {
  /**
   * Items of the element itself
   */
  own: T[]
  /**
   * Items of relationships of the element
   */
  relationships: Group<T>[]
  /**
   * Items inherited from children: of descendants and of relationships between them
   */
  inherited: Group<T>[]
}

function relationshipLabel(r: LikeC4Model.Relationship) {
  return (
    <>
      {r.source.title} → {r.target.title}
      {r.title && <Text component="span" c="dimmed" fz="xs">{`: ${r.title}`}</Text>}
    </>
  )
}

/**
 * Collects items of the element, its direct relationships and its children
 */
function collect<T>(
  element: LikeC4Model.Element,
  pick: (from: SecurityItemsSubject) => ReadonlyArray<T>,
  sort: (items: ReadonlyArray<T>) => T[],
): SecurityItemsOf<T> {
  const scope = elementSecurityScope(element)
  const relationshipGroup = (r: { relationship: LikeC4Model.Relationship } & SecurityItemsSubject) => ({
    key: r.relationship.id,
    label: relationshipLabel(r.relationship),
    items: sort(pick(r)),
  })
  return {
    own: sort(pick(scope.own)),
    relationships: scope.direct.map(relationshipGroup).filter(g => g.items.length > 0),
    inherited: [
      ...scope.descendants.map(d => ({
        key: d.element.id,
        label: d.element.title,
        items: sort(pick(d)),
      })),
      ...scope.internal.map(relationshipGroup),
    ].filter(g => g.items.length > 0),
  }
}

function countOf<T>(groups: Group<T>[]): number {
  return groups.reduce((acc, g) => acc + g.items.length, 0)
}

function totalOf<T>(data: SecurityItemsOf<T>): number {
  return data.own.length + countOf(data.relationships) + countOf(data.inherited)
}

const unsorted = <T,>(items: ReadonlyArray<T>): T[] => [...items]

/**
 * Number of items listed in the Vulnerabilities and Threats tabs:
 * items of the element, of its direct relationships and inherited from children
 */
export function securityItemCounts(element: LikeC4Model.Element): { vulnerabilities: number; threats: number } {
  return {
    vulnerabilities: totalOf(collect(element, e => e.vulnerabilities, unsorted)),
    threats: totalOf(collect(element, e => e.threats, unsorted)),
  }
}

function GroupList<T>({ groups, render }: { groups: Group<T>[]; render: (item: T, index: number) => ReactNode }) {
  return groups.map(({ key, label, items }) => (
    <Box key={key}>
      <Divider mb={8} labelPosition="left" variant="dashed" label={label} />
      <Stack gap="xs">
        {items.map(render)}
      </Stack>
    </Box>
  ))
}

function SecurityPanel<T>({
  data,
  summary,
  emptyText,
  render,
}: {
  data: SecurityItemsOf<T>
  summary: ReactNode
  emptyText: string
  render: (item: T, index: number) => ReactNode
}) {
  if (totalOf(data) === 0) {
    return (
      <Text c="dimmed" fz="sm" ta="center" py="xl">
        {emptyText}
      </Text>
    )
  }
  const inheritedCount = countOf(data.inherited)
  return (
    <Stack gap="md" pt="xs" pb="md">
      {summary}
      {data.own.length > 0 && (
        <Box>
          <Divider mb={8} labelPosition="left" variant="dashed" label="this element" />
          <Stack gap="xs">
            {data.own.map(render)}
          </Stack>
        </Box>
      )}
      <GroupList groups={data.relationships} render={render} />
      {inheritedCount > 0 && (
        <>
          <Divider
            mt="sm"
            labelPosition="left"
            size="sm"
            label={
              <Text fz="xs" fw={600} tt="uppercase" c="dimmed">
                inherited from children ({inheritedCount})
              </Text>
            } />
          <GroupList groups={data.inherited} render={render} />
        </>
      )}
    </Stack>
  )
}

const allItems = <T,>(data: SecurityItemsOf<T>): T[] => [
  ...data.own,
  ...data.relationships.flatMap(r => r.items),
  ...data.inherited.flatMap(r => r.items),
]

export function TabPanelVulnerabilities({ element }: { element: LikeC4Model.Element }) {
  const data = useMemo(
    () => collect(element, e => e.vulnerabilities, sortVulnerabilities),
    [element],
  )
  const all = useMemo(() => allItems(data), [data])
  return (
    <SecurityPanel
      data={data}
      summary={<VulnerabilitySummary vulnerabilities={all} />}
      emptyText="No known vulnerabilities"
      render={(v, i) => <VulnerabilityCard key={`${v.id}-${i}`} vulnerability={v} />}
    />
  )
}

export function TabPanelThreats({ element }: { element: LikeC4Model.Element }) {
  const data = useMemo(
    () => collect(element, e => e.threats, sortThreats),
    [element],
  )
  const all = useMemo(() => allItems(data), [data])
  return (
    <SecurityPanel
      data={data}
      summary={<StrideSummary threats={all} />}
      emptyText="No threats identified"
      render={(t, i) => <ThreatCard key={`${t.id}-${i}`} threat={t} />}
    />
  )
}
