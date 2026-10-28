import type { LikeC4Model } from '@likec4/core/model'
import type { Threat, Vulnerability } from '@likec4/core/types'
import { Box, Divider, Stack, Text } from '@mantine/core'
import { type ReactNode, useMemo } from 'react'
import {
  sortThreats,
  sortVulnerabilities,
  StrideSummary,
  ThreatCard,
  VulnerabilityCard,
  VulnerabilitySummary,
} from '../../components/security'

type SecurityItemsOf<T> = {
  own: T[]
  relationships: Array<{
    relationship: LikeC4Model.Relationship
    items: T[]
  }>
}

/**
 * Collects items of the element and its direct relationships (data flows)
 */
function collect<T>(
  element: LikeC4Model.Element,
  pick: (from: LikeC4Model.Element | LikeC4Model.Relationship) => ReadonlyArray<T>,
  sort: (items: ReadonlyArray<T>) => T[],
): SecurityItemsOf<T> {
  const relationships = [] as SecurityItemsOf<T>['relationships']
  const seen = new Set<string>()
  for (const relationship of [...element.incoming('direct'), ...element.outgoing('direct')]) {
    const items = pick(relationship)
    if (items.length > 0 && !seen.has(relationship.id)) {
      seen.add(relationship.id)
      relationships.push({ relationship, items: sort(items) })
    }
  }
  return {
    own: sort(pick(element)),
    relationships,
  }
}

function relationshipLabel(r: LikeC4Model.Relationship) {
  return (
    <>
      {r.source.title} → {r.target.title}
      {r.title && <Text component="span" c="dimmed" fz="xs">{`: ${r.title}`}</Text>}
    </>
  )
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
  const isEmpty = data.own.length === 0 && data.relationships.length === 0
  if (isEmpty) {
    return (
      <Text c="dimmed" fz="sm" ta="center" py="xl">
        {emptyText}
      </Text>
    )
  }
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
      {data.relationships.map(({ relationship, items }) => (
        <Box key={relationship.id}>
          <Divider mb={8} labelPosition="left" variant="dashed" label={relationshipLabel(relationship)} />
          <Stack gap="xs">
            {items.map(render)}
          </Stack>
        </Box>
      ))}
    </Stack>
  )
}

export function TabPanelVulnerabilities({ element }: { element: LikeC4Model.Element }) {
  const data = useMemo(
    () => collect(element, e => e.vulnerabilities, sortVulnerabilities),
    [element],
  )
  const all = useMemo(
    () => [...data.own, ...data.relationships.flatMap(r => r.items)] as Vulnerability[],
    [data],
  )
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
  const all = useMemo(
    () => [...data.own, ...data.relationships.flatMap(r => r.items)] as Threat[],
    [data],
  )
  return (
    <SecurityPanel
      data={data}
      summary={<StrideSummary threats={all} />}
      emptyText="No threats identified"
      render={(t, i) => <ThreatCard key={`${t.id}-${i}`} threat={t} />}
    />
  )
}
