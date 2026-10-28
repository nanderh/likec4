import type { ValidationCheck } from 'langium'
import { ast } from '../ast'
import { readSecurityAttribute, securityAttributesOf } from '../model/parser/security'
import type { LikeC4Services } from '../module'
import { tryOrLog } from './_shared'

export const checkSecurityProperty = (
  _: LikeC4Services,
): ValidationCheck<ast.SecurityProperty> => {
  return tryOrLog((node, accept) => {
    const what = ast.isThreatProperty(node) ? 'Threat' : 'Vulnerability'
    const props = node.$container.props
    const duplicate = props
      .slice(0, props.indexOf(node))
      .some(p => ast.isSecurityProperty(p) && p.$type === node.$type && p.id === node.id)
    if (duplicate) {
      accept('error', `${what} with id "${node.id}" is already defined`, {
        node,
        property: 'id',
      })
    }
    if (ast.isThreatProperty(node)) {
      const hasStride = node.body?.props.some(p => ast.isSecurityItemAttribute(p) && p.key === 'stride')
      if (!hasStride) {
        accept('warning', `Threat has no STRIDE category, add "stride spoofing, tampering, ..."`, {
          node,
          property: 'id',
        })
      }
    }
  })
}

export const checkSecurityItemAttribute = (
  _: LikeC4Services,
): ValidationCheck<ast.SecurityItemAttribute> => {
  return tryOrLog((node, accept) => {
    const item = node.$container.$container
    const spec = securityAttributesOf(item)
    const attrSpec = spec[node.key]
    if (!attrSpec) {
      accept('warning', `Unknown property "${node.key}", expected one of: ${Object.keys(spec).join(', ')}`, {
        node,
        property: 'key',
      })
      return
    }
    const first = node.$container.props.find(p => ast.isSecurityItemAttribute(p) && p.key === node.key)
    if (first !== node) {
      accept('warning', `Property "${node.key}" is already defined, ignored`, {
        node,
        property: 'key',
      })
      return
    }
    const { error } = readSecurityAttribute(attrSpec, node)
    if (error) {
      accept('error', error, {
        node,
        property: 'values',
      })
    }
  })
}
