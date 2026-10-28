import { css } from '@likec4/styles/css'
import { HStack } from '@likec4/styles/jsx'
import { Menu, Text } from '@mantine/core'
import { IconCheck, IconPalette } from '@tabler/icons-react'
import {
  type ColorByMode,
  type SecurityLevel,
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
            <Menu.Label>Legend (unresolved items)</Menu.Label>
            {SecurityLevels.map(level => (
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
