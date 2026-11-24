import type { LikeC4Model } from '@likec4/core/model'
import type { Threat, Vulnerability } from '@likec4/core/types'
import type { SecurityItemsSubject } from './summary'

type Element = LikeC4Model.Element
type Relationship = LikeC4Model.Relationship

export interface SecurityItemsOfElement extends SecurityItemsSubject {
  readonly element: Element
}

export interface SecurityItemsOfRelationship extends SecurityItemsSubject {
  readonly relationship: Relationship
}

/**
 * Threats and vulnerabilities around an element, as shown in element details
 */
export interface ElementSecurityScope {
  /**
   * Items of the element itself
   */
  readonly own: SecurityItemsSubject
  /**
   * Items of relationships with the element as source or target
   */
  readonly direct: ReadonlyArray<SecurityItemsOfRelationship>
  /**
   * Items inherited from children: own items of descendants
   */
  readonly descendants: ReadonlyArray<SecurityItemsOfElement>
  /**
   * Items inherited from children: relationships between descendants
   */
  readonly internal: ReadonlyArray<SecurityItemsOfRelationship>
}

function itemsOf(from: Element | Relationship): SecurityItemsSubject {
  return { threats: from.threats, vulnerabilities: from.vulnerabilities }
}

function isDescendantFqn(element: Element, fqn: string): boolean {
  return fqn.startsWith(element.id + '.')
}

const scopeCache = new WeakMap<Element, ElementSecurityScope>()

/**
 * Collects threats and vulnerabilities of the element, its direct relationships and its descendants
 */
export function elementSecurityScope(element: Element): ElementSecurityScope {
  let scope = scopeCache.get(element)
  if (scope) {
    return scope
  }
  const direct = [] as SecurityItemsOfRelationship[]
  const seen = new Set<string>()
  for (const relationship of [...element.incoming('direct'), ...element.outgoing('direct')]) {
    if (relationship.hasSecurity() && !seen.has(relationship.id)) {
      seen.add(relationship.id)
      direct.push({ relationship, ...itemsOf(relationship) })
    }
  }

  const descendants = [] as SecurityItemsOfElement[]
  const internal = [] as SecurityItemsOfRelationship[]
  for (const descendant of element.descendants('asc')) {
    if (descendant.hasSecurity()) {
      descendants.push({ element: descendant, ...itemsOf(descendant) })
    }
    for (const relationship of descendant.outgoing('direct')) {
      // relationships between descendants only, an element cannot relate to its ancestor
      if (
        relationship.hasSecurity()
        && isDescendantFqn(element, relationship.target.id)
        && !seen.has(relationship.id)
      ) {
        seen.add(relationship.id)
        internal.push({ relationship, ...itemsOf(relationship) })
      }
    }
  }

  scope = {
    own: itemsOf(element),
    direct,
    descendants,
    internal,
  }
  scopeCache.set(element, scope)
  return scope
}

function concat(groups: ReadonlyArray<SecurityItemsSubject>): SecurityItemsSubject {
  return {
    threats: groups.flatMap(g => g.threats) as Threat[],
    vulnerabilities: groups.flatMap(g => g.vulnerabilities) as Vulnerability[],
  }
}

/**
 * Items inherited from children: own items of descendants and items of relationships between them
 */
export function inheritedSecurityItems(scope: ElementSecurityScope): SecurityItemsSubject {
  return concat([...scope.descendants, ...scope.internal])
}

const rolledUpCache = new WeakMap<Element, SecurityItemsSubject>()

/**
 * Items of the element and everything inside it: own items, items of descendants
 * and of relationships between descendants.
 * Used by the node badge and "color by", so a collapsed parent shows the risk of its children.
 */
export function rolledUpSecurityItems(element: Element): SecurityItemsSubject {
  let items = rolledUpCache.get(element)
  if (items) {
    return items
  }
  const scope = elementSecurityScope(element)
  items = concat([scope.own, ...scope.descendants, ...scope.internal])
  rolledUpCache.set(element, items)
  return items
}

/**
 * Items of the element and of its direct relationships, without items of children.
 * Used for the scope element of a view that does not show the element itself.
 */
export function ownAndDirectSecurityItems(element: Element): SecurityItemsSubject {
  const scope = elementSecurityScope(element)
  return concat([scope.own, ...scope.direct])
}
