import type { DeploymentFqn, Fqn } from '@likec4/core'
import { scalar } from '@likec4/core'
import {
  highestSeverity,
  isUnresolvedSecurityStatus,
  threatRisk,
  vulnerabilitySeverity,
} from '@likec4/core/types'
import { css } from '@likec4/styles/css'
import { Badge, Tooltip } from '@mantine/core'
import { IconShieldExclamation } from '@tabler/icons-react'
import { useMemo } from 'react'
import { severityColor } from '../../../components/security'
import { useDiagram } from '../../../hooks/useDiagram'
import { useOptionalLikeC4Model } from '../../../hooks/useLikeC4Model'
import { DEPLOYMENT_DETAILS_TAB_KEY, ELEMENT_DETAILS_TAB_KEY } from '../../../overlays/element-details/subject'

const container = css({
  position: 'absolute',
  top: '1',
  left: '1',
  zIndex: '[1]',
  cursor: 'pointer',
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

/**
 * Shows the number of unresolved threats and vulnerabilities of the element.
 * Click opens element details on the corresponding tab.
 */
export function NodeSecurity(
  { id, data }: { id: string; data: { modelFqn?: Fqn | null; deploymentFqn?: DeploymentFqn | null } },
) {
  const diagram = useDiagram()
  const model = useOptionalLikeC4Model()
  const element = data.modelFqn ? model?.findElement(data.modelFqn) : null

  const summary = useMemo(() => {
    if (!element?.hasSecurity()) {
      return null
    }
    const threats = element.threats.filter(t => isUnresolvedSecurityStatus(t.status))
    const vulnerabilities = element.vulnerabilities.filter(v => isUnresolvedSecurityStatus(v.status))
    if (threats.length === 0 && vulnerabilities.length === 0) {
      return null
    }
    return {
      threats: threats.length,
      vulnerabilities: vulnerabilities.length,
      severity: highestSeverity([
        ...threats.map(threatRisk),
        ...vulnerabilities.map(vulnerabilitySeverity),
      ]),
    }
  }, [element])

  if (!summary) {
    return null
  }

  const label = [
    summary.vulnerabilities > 0 && `${summary.vulnerabilities} unresolved vulnerabilities`,
    summary.threats > 0 && `${summary.threats} unresolved threats`,
  ].filter(Boolean).join(', ')

  return (
    <Tooltip label={label} fz="xs" color="dark" withinPortal={false} openDelay={300}>
      <Badge
        className={container}
        size="sm"
        radius="sm"
        variant={summary.severity === 'critical' ? 'filled' : 'light'}
        color={summary.severity ? severityColor[summary.severity] : 'gray'}
        leftSection={<IconShieldExclamation size={12} stroke={2} />}
        onPointerDown={e => e.stopPropagation()}
        onDoubleClick={e => e.stopPropagation()}
        onClick={e => {
          e.stopPropagation()
          try {
            // Open details on the relevant tab (stored by useSessionStorage in ElementDetailsCard)
            const tab = summary.vulnerabilities > 0 && summary.threats === 0 ? 'Vulnerabilities' : 'Threats'
            const key = data.deploymentFqn ? DEPLOYMENT_DETAILS_TAB_KEY : ELEMENT_DETAILS_TAB_KEY
            window.sessionStorage.setItem(key, JSON.stringify(tab))
          } catch {
            // ignore, details will open on the last active tab
          }
          diagram.openNodeDetails(scalar.NodeId(id))
        }}
      >
        {summary.threats + summary.vulnerabilities}
      </Badge>
    </Tooltip>
  )
}
