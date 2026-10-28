import type { Fqn } from '@likec4/core'
import { securityLevel, securityLevelColor } from '../../../components/security'
import { selectDiagramContext, useDiagramSelector } from '../../../hooks/useDiagram'
import { useOptionalLikeC4Model } from '../../../hooks/useLikeC4Model'

const selectColorBy = selectDiagramContext(c => c.colorBy)

/**
 * Returns `data-likec4-color` override for the node, if "color by" mode is active.
 * Nodes without a logical element (e.g. deployment nodes) are muted.
 */
export function useColorByOverride(modelFqn: Fqn | null | undefined): { 'data-likec4-color'?: string } {
  const colorBy = useDiagramSelector(selectColorBy)
  const model = useOptionalLikeC4Model()
  if (colorBy === 'default' || !model?.hasSecurity()) {
    return {}
  }
  const element = modelFqn ? model.findElement(modelFqn) : null
  return {
    'data-likec4-color': securityLevelColor(element ? securityLevel(element, colorBy) : 'none'),
  }
}
