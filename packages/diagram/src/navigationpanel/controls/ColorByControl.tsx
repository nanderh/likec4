import { type RiskLevel, riskScore } from '@likec4/core/types'
import { css } from '@likec4/styles/css'
import { HStack } from '@likec4/styles/jsx'
import { Box, Menu, Text } from '@mantine/core'
import { IconCheck, IconPalette } from '@tabler/icons-react'
import {
  type ColorByMode,
  type SecurityLevel,
  riskScoreLevel,
  RiskScoreOtherLevels,
  securityLevelLabels,
  SecurityLevels,
  SecurityPalette,
} from '../../components/security'
import { selectDiagramContext, useDiagram, useDiagramSelector } from '../../hooks/useDiagram'
import { useOptionalLikeC4Model } from '../../hooks/useLikeC4Model'
import { PanelActionIcon, Tooltip } from '../_common'

const modes = [
  { value: 'default', label: 'Element colors' },
  { value: 'security', label: 'Highest risk (all)' },
  { value: 'vulnerabilities', label: 'Vulnerability severity' },
  { value: 'threats', label: 'Threat risk' },
  { value: 'risk-score', label: 'Risk score (likelihood × impact)' },
] as const satisfies ReadonlyArray<{ value: ColorByMode; label: string }>

const swatch = css({
  display: 'inline-block',
  width: '[12px]',
  height: '[12px]',
  borderRadius: '[3px]',
  flexShrink: 0,
})

function swatchColor(level: SecurityLevel): string {
  return level === 'none' ? 'var(--mantine-color-gray-5)' : SecurityPalette[`likec4-security-${level}`]
}

const matrix = css({
  display: 'grid',
  gridTemplateColumns: 'max-content repeat(4, 24px)',
  justifyContent: 'start',
  gap: '[2px]',
  alignItems: 'center',
  fontSize: '[10px]',
  lineHeight: '1',
})

const matrixCell = css({
  height: '[18px]',
  borderRadius: '[2px]',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  fontWeight: 'semibold',
  color: 'white',
})

const matrixLabel = css({
  color: 'text.dimmed',
  textAlign: 'center',
})

// rows from high to low likelihood, columns from low to high impact
const likelihoodRows = ['critical', 'high', 'medium', 'low'] as const satisfies ReadonlyArray<RiskLevel>
const impactColumns = ['low', 'medium', 'high', 'critical'] as const satisfies ReadonlyArray<RiskLevel>
const shortLevel = { low: 'low', medium: 'med', high: 'high', critical: 'crit' } as const satisfies Record<
  RiskLevel,
  string
>

/**
 * Risk matrix: likelihood × impact, each cell in the color of its score
 */
function RiskMatrixLegend() {
  return (
    <Box px="3" py="1">
      <div className={matrix} role="table" aria-label="Risk matrix: likelihood by impact">
        {likelihoodRows.map(likelihood => (
          <div key={likelihood} role="row" style={{ display: 'contents' }}>
            <Text fz={10} c="dimmed" pr={4} role="rowheader">{likelihood}</Text>
            {impactColumns.map(impact => {
              const score = riskScore(likelihood, impact)
              return (
                <div
                  key={impact}
                  role="cell"
                  className={matrixCell}
                  style={{ background: swatchColor(riskScoreLevel(score)) }}
                  title={`likelihood ${likelihood} × impact ${impact} = ${score}`}>
                  {score}
                </div>
              )
            })}
          </div>
        ))}
        <span />
        {impactColumns.map(impact => <span key={impact} className={matrixLabel}>{shortLevel[impact]}</span>)}
      </div>
      <Text fz={10} c="dimmed" mt={4} maw={200}>
        rows: likelihood, columns: impact. Threats without both use their risk level (low 1, medium 4, high 9, critical
        16).
      </Text>
    </Box>
  )
}

const selectColorBy = selectDiagramContext(c => c.colorBy)

/**
 * Switches node coloring between element colors and security data (like label sets).
 * Rendered only if the model has vulnerabilities or threats.
 */
export function ColorByControl() {
  const diagram = useDiagram()
  const model = useOptionalLikeC4Model()
  const colorBy = useDiagramSelector(selectColorBy)

  if (!model?.hasSecurity()) {
    return null
  }
  const active = colorBy !== 'default'

  return (
    <Menu
      withinPortal={false} // if we render menu in portal, NavigationPanelDropdown receives onMouseLeave event
      floatingStrategy="absolute"
      shadow="lg"
      position="bottom-end"
      offset={{ mainAxis: 4 }}
      closeOnItemClick
    >
      <Menu.Target>
        <Tooltip label="Color by">
          <PanelActionIcon
            layout="position"
            variant={active ? 'filled' : 'default'}
            aria-label="Color by"
            children={<IconPalette style={{ width: '60%', height: '60%' }} />}
          />
        </Tooltip>
      </Menu.Target>
      <Menu.Dropdown>
        <Menu.Label>Color by</Menu.Label>
        {modes.map(mode => (
          <Menu.Item
            key={mode.value}
            fz="sm"
            leftSection={colorBy === mode.value
              ? <IconCheck size={14} />
              : <span style={{ display: 'inline-block', width: 14 }} />}
            onClick={e => {
              e.stopPropagation()
              diagram.switchColorBy(mode.value)
            }}
          >
            {mode.label}
          </Menu.Item>
        ))}
        {active && (
          <>
            <Menu.Divider />
            <Menu.Label>
              {colorBy === 'risk-score' ? 'Legend (highest unresolved threat)' : 'Legend (worst unresolved item)'}
            </Menu.Label>
            {colorBy === 'risk-score' && <RiskMatrixLegend />}
            {(colorBy === 'risk-score' ? RiskScoreOtherLevels : SecurityLevels).map(level => (
              <HStack key={level} gap="2" px="3" py="0.5">
                <span className={swatch} style={{ background: swatchColor(level) }} />
                <Text fz="xs">{securityLevelLabels[level]}</Text>
              </HStack>
            ))}
          </>
        )}
      </Menu.Dropdown>
    </Menu>
  )
}
