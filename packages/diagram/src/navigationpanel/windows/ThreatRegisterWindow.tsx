import { HStack } from '@likec4/styles/jsx'
import { ActionIcon, Button, ScrollArea, Text, Tooltip } from '@mantine/core'
import { IconDownload, IconFilterOff, IconId } from '@tabler/icons-react'
import { useMemo, useState } from 'react'
import {
  type RegisterFilters,
  type RegisterRow,
  type RegisterSort,
  buildSecurityRegister,
  downloadRegisterCsv,
  filterRegister,
  hasActiveRegisterFilters,
  pickRegisterView,
  registerToCsv,
  SecurityRegisterTable,
  sortRegister,
} from '../../components/security'
import { useDiagram } from '../../hooks/useDiagram'
import { useLikeC4Model } from '../../hooks/useLikeC4Model'
import { ELEMENT_DETAILS_TAB_KEY } from '../../overlays/element-details/subject'

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
  const filtersActive = hasActiveRegisterFilters(filters)

  const showInView = (row: RegisterRow) => {
    setSelected(row.key)
    const currentViewId = diagram.currentView.id
    const owner = row.owner
    if (owner.type === 'element') {
      const element = model.findElement(owner.fqn)
      const view = element ? pickRegisterView(element.views(), { currentViewId, scope: owner.fqn }) : null
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
    const view = relationship ? pickRegisterView(relationship.views(), { currentViewId }) : null
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
            onClick={() => downloadRegisterCsv(registerToCsv(rows), `threat-register-${model.projectId}.csv`)}>
            Export CSV
          </Button>
        </HStack>
      </HStack>
      <ScrollArea style={{ flex: 1 }} scrollbars="xy" type="auto" overscrollBehavior="contain">
        <SecurityRegisterTable
          className="nodrag"
          rows={rows}
          sort={sort}
          onSortChange={setSort}
          filters={filters}
          onFiltersChange={setFilters}
          selected={selected}
          onRowClick={showInView}
          renderActions={r => (
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
          )}
        />
        {rows.length === 0 && (
          <Text fz="sm" c="dimmed" ta="center" py="xl">
            No items match the filters
          </Text>
        )}
      </ScrollArea>
    </>
  )
}
