import { css } from '@likec4/styles/css'
import { Badge, Tooltip } from '@mantine/core'
import { IconShieldExclamation, IconShieldHalfFilled } from '@tabler/icons-react'
import { useMemo } from 'react'
import {
  elementSecurityScope,
  ownAndDirectSecurityItems,
  securityBadgeSummary,
  severityColor,
} from '../../components/security'
import type { CurrentViewModel } from '../../hooks/useCurrentViewModel'
import { useDiagram } from '../../hooks/useDiagram'
import { ELEMENT_DETAILS_TAB_KEY } from '../../overlays/element-details/subject'

const container = css({
  display: 'flex',
  gap: '1',
  alignItems: 'center',
  flexShrink: 0,
  cursor: 'pointer',
})

function plural(count: number, singular: string, pluralForm: string) {
  return `${count} ${count === 1 ? singular : pluralForm}`
}

/**
 * Security summary of the scope element of a view (`view ... of gateway`),
 * when the view does not show that element, for example when its children are in groups.
 * Counts items of the element and of its relationships; items of children are on their own nodes.
 * Click opens the element details.
 */
export function ViewScopeSecurity({ viewModel }: { viewModel: CurrentViewModel | null }) {
  const diagram = useDiagram()

  const data = useMemo(() => {
    if (!viewModel?.isScopedElementView()) {
      return null
    }
    const scope = viewModel.viewOf
    if (viewModel.includesElement(scope.id)) {
      return null
    }
    const summary = securityBadgeSummary(ownAndDirectSecurityItems(scope))
    if (!summary) {
      return null
    }
    const own = securityBadgeSummary(elementSecurityScope(scope).own)
    return { scope, summary, own }
  }, [viewModel])

  if (!data) {
    return null
  }
  const { scope, summary, own } = data
  const unresolved = summary.threats + summary.vulnerabilities
  const ownUnresolved = own ? own.threats + own.vulnerabilities : 0

  const label = [
    `${scope.title} is not shown in this view.`,
    unresolved > 0 &&
    `${plural(ownUnresolved, 'unresolved item', 'unresolved items')} on the element, ${
      unresolved - ownUnresolved
    } on its relationships.`,
    summary.carried > 0 && `${plural(summary.carried, 'item', 'items')} with risk carried.`,
    'Click for details.',
  ].filter(Boolean).join(' ')

  const openDetails = (e: { stopPropagation(): void }) => {
    e.stopPropagation()
    try {
      const tab = summary.vulnerabilities > 0 && summary.threats === 0 ? 'Vulnerabilities' : 'Threats'
      sessionStorage.setItem(ELEMENT_DETAILS_TAB_KEY, JSON.stringify(tab))
    } catch {
      // ignore, details open on the last active tab
    }
    diagram.openNodeDetails({ type: 'element', element: scope.id })
  }

  return (
    <Tooltip label={label} fz="xs" color="dark" multiline maw={280} withinPortal={false} openDelay={300}>
      <div
        className={container}
        role="button"
        tabIndex={0}
        aria-label={label}
        data-testid="view-scope-security"
        onClick={openDetails}
        onKeyDown={e => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault()
            openDetails(e)
          }
        }}>
        {unresolved > 0 && (
          <Badge
            size="sm"
            radius="sm"
            variant={summary.severity === 'critical' ? 'filled' : 'light'}
            color={summary.severity ? severityColor[summary.severity] : 'gray'}
            leftSection={<IconShieldExclamation size={12} stroke={2} />}>
            {unresolved}
          </Badge>
        )}
        {summary.carried > 0 && (
          <Badge
            size="sm"
            radius="sm"
            variant="outline"
            color="gray"
            leftSection={<IconShieldHalfFilled size={12} stroke={2} />}>
            {summary.carried}
          </Badge>
        )}
      </div>
    </Tooltip>
  )
}
