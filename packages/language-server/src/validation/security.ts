import { type ProjectId, FqnRef } from '@likec4/core'
import { type AstNode, type ValidationCheck, AstUtils, DocumentState, WorkspaceCache } from 'langium'
import { type ParsedLikeC4LangiumDocument, ast } from '../ast'
import { readSecurityAttribute, securityAttributesOf } from '../model/parser/security'
import { relationFingerprint } from '../model/relationFingerprint'
import type { LikeC4Services } from '../module'
import { projectIdFrom } from '../utils'
import { tryOrLog } from './_shared'

/**
 * Element or relationship a threat or vulnerability is defined on
 */
type SecurityOwner = {
  /**
   * Same for an element and its `extend` blocks, and for a relationship and its `extend` blocks
   */
  readonly key: string
  readonly label: string
}

type SecurityItemDefinition = {
  readonly owner: SecurityOwner
  /**
   * Location of the block with the definition: element, relationship or extend
   */
  readonly uri: string
  readonly astPath: string
}

/**
 * Definitions of threats (`threat:<id>`) and vulnerabilities (`vulnerability:<id>`) in the project
 */
type SecurityItemsIndex = Map<string, SecurityItemDefinition[]>

const indexKey = (node: ast.SecurityProperty) => `${ast.isThreatProperty(node) ? 'threat' : 'vulnerability'}:${node.id}`

function buildSecurityItemsIndex(docs: ReadonlyArray<ParsedLikeC4LangiumDocument>): SecurityItemsIndex {
  const index: SecurityItemsIndex = new Map()
  const relationLabels = new Map<string, string>()
  for (const doc of docs) {
    for (const rel of doc.c4Relations) {
      const label = `${FqnRef.flatten(rel.source)} -> ${FqnRef.flatten(rel.target)}`
      relationLabels.set(relationFingerprint(rel), rel.title ? `${label} '${rel.title}'` : label)
    }
  }

  const add = (
    owner: SecurityOwner,
    uri: string,
    astPath: string,
    items: { threats?: ReadonlyArray<{ id: string }>; vulnerabilities?: ReadonlyArray<{ id: string }> },
  ) => {
    const entries = [
      ...(items.threats ?? []).map(t => `threat:${t.id}`),
      ...(items.vulnerabilities ?? []).map(v => `vulnerability:${v.id}`),
    ]
    for (const key of entries) {
      let definitions = index.get(key)
      if (!definitions) {
        definitions = []
        index.set(key, definitions)
      }
      definitions.push({ owner, uri, astPath })
    }
  }

  for (const doc of docs) {
    const uri = doc.uri.toString()
    for (const el of doc.c4Elements) {
      add({ key: `element:${el.id}`, label: el.id }, uri, el.astPath, el)
    }
    for (const ext of doc.c4ExtendElements) {
      add({ key: `element:${ext.id}`, label: ext.id }, uri, ext.astPath, ext)
    }
    for (const rel of doc.c4Relations) {
      const key = relationFingerprint(rel)
      add({ key: `relation:${key}`, label: relationLabels.get(key) ?? 'relationship' }, uri, rel.astPath, rel)
    }
    for (const ext of doc.c4ExtendRelations) {
      add(
        { key: `relation:${ext.id}`, label: relationLabels.get(ext.id) ?? 'relationship (extend)' },
        uri,
        ext.astPath,
        ext,
      )
    }
  }
  return index
}

export const checkSecurityProperty = (
  services: LikeC4Services,
): ValidationCheck<ast.SecurityProperty> => {
  const modelParser = services.likec4.ModelParser
  const locator = services.workspace.AstNodeLocator
  const cache = new WorkspaceCache<ProjectId, SecurityItemsIndex>(services.shared, DocumentState.Linked)

  const indexOf = (projectId: ProjectId) =>
    cache.get(projectId, () => buildSecurityItemsIndex(modelParser.documents(projectId).toArray()))

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
    } else {
      checkDuplicateInProject(node, what)
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

    /**
     * Warns when the id is defined on other elements or relationships of the project,
     * or in another block (e.g. `extend`) of the same element or relationship.
     */
    function checkDuplicateInProject(node: ast.SecurityProperty, what: string) {
      const doc = AstUtils.getDocument(node)
      // Body of the element, relationship or extend
      const ownerNode: AstNode | undefined = node.$container.$container
      if (!ownerNode) {
        return
      }
      const definitions = indexOf(projectIdFrom(doc)).get(indexKey(node)) ?? []
      if (definitions.length < 2) {
        return
      }
      const uri = doc.uri.toString()
      const astPath = locator.getAstNodePath(ownerNode)
      const own = definitions.find(d => d.uri === uri && d.astPath === astPath)
      if (!own) {
        return
      }
      const others = [
        ...new Map(
          definitions
            .filter(d => d.owner.key !== own.owner.key)
            .map(d => [d.owner.key, d.owner.label]),
        ).values(),
      ]
      if (others.length > 0) {
        accept(
          'warning',
          `${what} id "${node.id}" is also defined on ${others.join(', ')}; ids should be unique in the project`,
          { node, property: 'id' },
        )
        return
      }
      const elsewhere = definitions.some(d => d.owner.key === own.owner.key && d !== own)
      if (elsewhere) {
        accept(
          'warning',
          `${what} id "${node.id}" is defined more than once for ${own.owner.label} (also in an extend), only the first definition is used`,
          { node, property: 'id' },
        )
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
