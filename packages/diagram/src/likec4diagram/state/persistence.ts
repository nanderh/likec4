import { isBoolean, pickBy } from 'remeda'
import { type ColorByMode, ColorByModes } from '../../components/security/colorBy'
import type { EnabledFeatures } from '../../context/DiagramFeatures'

const key = `likec4:diagram:toggledFeatures`
export const DiagramToggledFeaturesPersistence = {
  read() {
    try {
      let fromStorage = sessionStorage.getItem(key)
      if (fromStorage) {
        return JSON.parse(fromStorage) as Partial<EnabledFeatures>
      }
      return null
    } catch (e) {
      if (import.meta.env.MODE !== 'test') {
        console.error(`Error reading fromStorage ${key}:`, e)
      }

      return null
    }
  },
  write<F extends Partial<EnabledFeatures>>(toggledFeatures: F): F {
    sessionStorage.setItem(key, JSON.stringify(pickBy(toggledFeatures, isBoolean)))
    return toggledFeatures
  },
}

const colorByKey = `likec4:diagram:colorBy`
export const DiagramColorByPersistence = {
  read(): ColorByMode | null {
    try {
      const fromStorage = sessionStorage.getItem(colorByKey)
      return ColorByModes.find(m => m === fromStorage) ?? null
    } catch {
      return null
    }
  },
  write(mode: ColorByMode): ColorByMode {
    try {
      sessionStorage.setItem(colorByKey, mode)
    } catch {
      // ignore
    }
    return mode
  },
}
