import type { DeploymentFqn, Fqn } from '@likec4/core'
import { scalar } from '@likec4/core'
import { css } from '@likec4/styles/css'
import { Badge, Tooltip } from '@mantine/core'
import { IconShieldExclamation, IconShieldHalfFilled } from '@tabler/icons-react'
import type { MouseEvent, PointerEvent } from 'react'
import { useMemo } from 'react'
import {
  type SecurityBadgeSummary,
  rolledUpSecurityItems,
  securityBadgeSummary,
  severityColor,
} from '../../../components/security'
import { useDiagram } from '../../../hooks/useDiagram'
import { useOptionalLikeC4Model } from '../../../hooks/useLikeC4Model'
import { DEPLOYMENT_DETAILS_TAB_KEY, ELEMENT_DETAILS_TAB_KEY } from '../../../overlays/element-details/subject'

const container = css({
  position: 'absolute',
  top: '1',
  left: '1',
  zIndex: '[1]',
  display: 'flex',
  gap: '1',
  alignItems: 'center',
  _shapeCylinder: {
    top: '[16px]',
  },
  _shapeStorage: {
    top: '[16px]',
  },
  _shapeQueue: {
    left: '3',
  },
  _smallZoom: {
    display: 'none',
  },
})

const badge = css({
  cursor: 'pointer',
})

const stop = (e: PointerEvent | MouseEvent) => e.stopPropagation()

/**
 * "3 unresolved threats (1 own, 2 from children)"
 */
function countLabel(total: number, own: number, singular: string, plural: string) {
  const what = `${total} ${total === 1 ? singular : plural}`
  return own === total ? what : `${what} (${own} own, ${total - own} from children)`
}

function unresolvedLabel(summary: SecurityBadgeSummary, own: SecurityBadgeSummary | null) {
  const { vulnerabilities, threats } = summary
  return [
    vulnerabilities > 0 && countLabel(
      vulnerabilities,
      own?.vulnerabilities ?? 0,
      'unresolved vulnerability',
      'unresolved vulnerabilities',
    ),
    threats > 0 && countLabel(threats, own?.threats ?? 0, 'unresolved threat', 'unresolved threats'),
  ].filter(Boolean).join(', ')
}

/**
 * Shows the number of unresolved threats and vulnerabilities of the element and everything inside it,
 * and a muted marker when some risk is carried (accepted or transferred).
 * Click opens element details on the corresponding tab.
 */
export function NodeSecurity(
  { id, data }: { id: string; data: { modelFqn?: Fqn | null; deploymentFqn?: DeploymentFqn | null } },
) {
  const diagram = useDiagram()
  const model = useOptionalLikeC4Model()
  const element = data.modelFqn ? model?.findElement(data.modelFqn) : null

  const [summary, own] = useMemo(() => {
    if (!element) {
      return [null, null]
    }
    const rolledUp = securityBadgeSummary(rolledUpSecurityItems(element))
    return [rolledUp, rolledUp && element.hasSecurity() ? securityBadgeSummary(element) : null]
  }, [element])

  if (!summary) {
    return null
  }

  const openDetails = (e: MouseEvent, tab: 'Threats' | 'Vulnerabilities') => {
    e.stopPropagation()
    try {
      // Open details on the relevant tab (stored by useSessionStorage in ElementDetailsCard)
      const key = data.deploymentFqn ? DEPLOYMENT_DETAILS_TAB_KEY : ELEMENT_DETAILS_TAB_KEY
      window.sessionStorage.setItem(key, JSON.stringify(tab))
    } catch {
      // ignore, details will open on the last active tab
    }
    diagram.openNodeDetails(scalar.NodeId(id))
  }

  const unresolved = summary.threats + summary.vulnerabilities
  const unresolvedTab = summary.vulnerabilities > 0 && summary.threats === 0 ? 'Vulnerabilities' : 'Threats'

  return (
    <div className={container} onPointerDown={stop} onDoubleClick={stop}>
      {unresolved > 0 && (
        <Tooltip label={unresolvedLabel(summary, own)} fz="xs" color="dark" withinPortal={false} openDelay={300}>
          <Badge
            className={badge}
            size="sm"
            radius="sm"
            variant={summary.severity === 'critical' ? 'filled' : 'light'}
            color={summary.severity ? severityColor[summary.severity] : 'gray'}
            leftSection={<IconShieldExclamation size={12} stroke={2} />}
            onClick={e =>
              openDetails(e, unresolvedTab)}
          >
            {unresolved}
          </Badge>
        </Tooltip>
      )}
      {summary.carried > 0 && (
        <Tooltip
          label={countLabel(
            summary.carried,
            own?.carried ?? 0,
            'item with risk carried',
            'items with risk carried',
          ) + ' (accepted or transferred)'}
          fz="xs"
          color="dark"
          withinPortal={false}
          openDelay={300}>
          <Badge
            className={badge}
            data-security-carried
            size="sm"
            radius="sm"
            variant="outline"
            color="gray"
            leftSection={<IconShieldHalfFilled size={12} stroke={2} />}
            onClick={e => openDetails(e, 'Threats')}
          >
            {summary.carried}
          </Badge>
        </Tooltip>
      )}
    </div>
  )
}
