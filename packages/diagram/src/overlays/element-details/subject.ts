import type { DeploymentFqn, Fqn } from '@likec4/core'
import type { BaseNodeData } from '../../base/types'

export type DetailsSubject =
  | { type: 'element'; element: Fqn; deployment?: never }
  | { type: 'deployment'; deployment: DeploymentFqn; element?: never }

export function detailsSubject(
  data: BaseNodeData & {
    modelFqn?: Fqn | null | undefined
    deploymentFqn?: DeploymentFqn | null | undefined
  },
): DetailsSubject | null {
  if (data.deploymentFqn) {
    return { type: 'deployment', deployment: data.deploymentFqn }
  }
  return data.modelFqn ? { type: 'element', element: data.modelFqn } : null
}

/**
 * Session storage key of the active tab in element details
 */
export const ELEMENT_DETAILS_TAB_KEY = 'likec4:element-details:active-tab'

/**
 * Session storage key of the active tab in deployment element details
 */
export const DEPLOYMENT_DETAILS_TAB_KEY = 'likec4:deployment-details:active-tab'
