import { useDisclosure } from '@mantine/hooks'
import { IconListDetails } from '@tabler/icons-react'
import { useState } from 'react'
import { clamp } from 'remeda'
import { FloatingWindow } from '../../components/FloatingWindow'
import { useRootContainer } from '../../context'
import { useOptionalLikeC4Model } from '../../hooks/useLikeC4Model'
import { PanelActionIcon, Tooltip } from '../_common'
import { ThreatRegisterWindow } from '../windows/ThreatRegisterWindow'

/**
 * Opens the threat register, a window with all threats and vulnerabilities of the project.
 * Rendered only if the model has vulnerabilities or threats.
 */
export function ThreatRegisterButton({ onOpen }: { onOpen?: () => void }) {
  const model = useOptionalLikeC4Model()
  const { ref: rootRef } = useRootContainer()
  const [opened, handlers] = useDisclosure(false)

  const [windowProps, setWindowProps] = useState({
    dimensions: {
      initialWidth: 960,
      initialHeight: 480,
      minWidth: 480,
      minHeight: 240,
    },
    initialPosition: {
      top: 80,
      left: 32,
    },
  })

  if (!model?.hasSecurity()) {
    return null
  }

  const toggle = () => {
    if (opened) {
      handlers.close()
      return
    }
    const rootElement = rootRef.current
    if (rootElement) {
      const viewport = rootElement.getBoundingClientRect()
      const panelRect = rootElement.querySelector('[data-panel="navigation"]')?.getBoundingClientRect()
      setWindowProps(({ dimensions, initialPosition }) => ({
        dimensions: {
          ...dimensions,
          initialWidth: clamp(viewport.width * 0.7, { min: 480, max: 1200 }),
          initialHeight: clamp(viewport.height * 0.5, { min: 240, max: 640 }),
        },
        initialPosition: panelRect
          ? { top: panelRect.bottom + 10, left: panelRect.left }
          : initialPosition,
      }))
    }
    handlers.open()
    onOpen?.()
  }

  return (
    <>
      <Tooltip label="Threat register">
        <PanelActionIcon
          layout="position"
          variant={opened ? 'filled' : 'default'}
          aria-label="Threat register"
          onClick={e => {
            e.stopPropagation()
            toggle()
          }}>
          <IconListDetails style={{ width: '60%', height: '60%' }} />
        </PanelActionIcon>
      </Tooltip>
      {opened && (
        <FloatingWindow windowId="threat-register" {...windowProps} onClose={handlers.close}>
          <ThreatRegisterWindow />
        </FloatingWindow>
      )}
    </>
  )
}
