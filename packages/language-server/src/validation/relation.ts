// SPDX-License-Identifier: MIT
//
// Copyright (c) 2023-2026 Denis Davydkov
// Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
//
// Portions of this file have been modified by NVIDIA CORPORATION & AFFILIATES.

import { type ProjectId, FqnRef, isSameHierarchy } from '@likec4/core'
import { type ValidationCheck, AstUtils, DocumentState, WorkspaceCache } from 'langium'
import { flatMap, map, pipe } from 'remeda'
import { ast } from '../ast'
import { relationFingerprint } from '../model/relationFingerprint'
import type { LikeC4Services } from '../module'
import { projectIdFrom, safeCall } from '../utils'
import { tryOrLog } from './_shared'

export const relationChecks = (services: LikeC4Services): ValidationCheck<ast.Relation> => {
  const modelParser = services.likec4.ModelParser

  return tryOrLog((el, accept) => {
    const parser = modelParser.forDocument(AstUtils.getDocument(el))

    const source = safeCall(() => parser._resolveRelationSource(el))
    if (!source) {
      accept('error', 'Source not resolved', {
        node: el,
        property: 'source',
      })
      return
    }
    const target = safeCall(() => parser.parseFqnRef(el.target))
    if (!target) {
      accept('error', 'Target not resolved', {
        node: el,
        property: 'target',
      })
      return
    }

    if (FqnRef.isImportRef(source)) {
      if (FqnRef.isImportRef(target)) {
        accept('warning', 'Relationship between imported elements may not be visible in origin projects', {
          node: el,
        })
      } else {
        accept('warning', 'Relationship from imported element to local element may not be visible in origin project', {
          node: el,
          property: 'source',
        })
      }
    }

    if (isSameHierarchy(FqnRef.flatten(source), FqnRef.flatten(target))) {
      accept('error', 'Invalid parent-child relationship', {
        node: el,
      })
    }
  })
}

export const checkRelationBody = (_services: LikeC4Services): ValidationCheck<ast.RelationBody> => {
  return tryOrLog((body, accept) => {
    const relation = body.$container
    if (relation.tags?.values && body.tags?.values) {
      accept('error', 'Relation cannot have tags in both header and body', {
        node: body.tags,
      })
    }
  })
}

type RelationSummary = {
  readonly source: string
  readonly target: string
  readonly title: string
  readonly kind: string
  readonly isBidirectional: boolean
}

type ProjectRelations = {
  readonly fingerprints: Set<string>
  readonly relations: ReadonlyArray<RelationSummary>
}

/**
 * Edit distance between two strings, case insensitive
 */
export function editDistance(a: string, b: string): number {
  a = a.toLowerCase()
  b = b.toLowerCase()
  let previous = Array.from({ length: b.length + 1 }, (_, j) => j)
  for (let i = 1; i <= a.length; i++) {
    const current = [i]
    for (let j = 1; j <= b.length; j++) {
      current[j] = Math.min(
        previous[j]! + 1,
        current[j - 1]! + 1,
        previous[j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1),
      )
    }
    previous = current
  }
  return previous[b.length]!
}

function formatRelation(r: RelationSummary): string {
  const arrow = r.isBidirectional ? '<->' : '->'
  const title = r.title ? ` '${r.title}'` : ''
  const kind = r.kind !== 'default' ? ` [${r.kind}]` : ''
  return `${r.source} ${arrow} ${r.target}${title}${kind}`
}

/**
 * Relations closest to an extend that matches nothing:
 * relations between the same elements if there are any, otherwise relations from the same source
 * or to the same target; ordered by similarity of the title.
 */
export function nearestRelations(
  relations: ReadonlyArray<RelationSummary>,
  extend: { source: string; target: string; title: string },
  limit = 3,
): RelationSummary[] {
  const { source, target, title } = extend
  const sameEndpoints = relations.filter(r =>
    (r.source === source && r.target === target) || (r.source === target && r.target === source)
  )
  const candidates = sameEndpoints.length > 0
    ? sameEndpoints
    : relations.filter(r => r.source === source || r.target === target)
  return candidates
    .map(r => ({ r, distance: editDistance(r.title, title) }))
    .sort((a, b) => a.distance - b.distance)
    .slice(0, limit)
    .map(({ r }) => r)
}

export const extendRelationChecks = (services: LikeC4Services): ValidationCheck<ast.ExtendRelation> => {
  const modelParser = services.likec4.ModelParser

  const cache = new WorkspaceCache<ProjectId, ProjectRelations>(services.shared, DocumentState.Linked)

  function getProjectRelations(projectId: ProjectId): ProjectRelations {
    return cache.get(projectId, () => {
      const relations = pipe(
        services.shared.workspace.LangiumDocuments.projectDocuments(projectId).toArray(),
        flatMap(doc => doc.c4Relations ?? []),
      )
      return {
        fingerprints: new Set(map(relations, rel => relationFingerprint(rel))),
        relations: map(relations, rel => ({
          source: FqnRef.flatten(rel.source),
          target: FqnRef.flatten(rel.target),
          title: rel.title ?? '',
          kind: rel.kind ?? 'default',
          isBidirectional: !!rel.isBidirectional,
        })),
      }
    })
  }

  return tryOrLog((el, accept) => {
    const doc = AstUtils.getDocument(el)
    const parser = modelParser.forDocument(doc)

    const source = safeCall(() => parser.parseFqnRef(el.source))
    if (!source) {
      accept('error', 'Source not resolved', {
        node: el,
        property: 'source',
      })
      return
    }
    const target = safeCall(() => parser.parseFqnRef(el.target))
    if (!target) {
      accept('error', 'Target not resolved', {
        node: el,
        property: 'target',
      })
      return
    }

    if (!FqnRef.isModelRef(source) && !FqnRef.isImportRef(source)) {
      accept('error', 'Source must reference a model element', {
        node: el,
        property: 'source',
      })
      return
    }

    if (!FqnRef.isModelRef(target) && !FqnRef.isImportRef(target)) {
      accept('error', 'Target must reference a model element', {
        node: el,
        property: 'target',
      })
      return
    }

    const projectId = projectIdFrom(doc)

    // Warn if this extend does not match any relation in the workspace
    // Build a match key identical to buildModel.ts
    const kind = (el.kind ?? el.dotKind?.kind)?.ref?.name ?? 'default'
    // Normalize title using the same parser helper
    const { title = '' } = parser.parseBaseProps({}, { title: el.title })

    const extendKey = relationFingerprint({
      source,
      target,
      kind,
      title,
      isBidirectional: el.isBidirectional || undefined,
    })

    const { fingerprints, relations } = getProjectRelations(projectId)
    if (!fingerprints.has(extendKey)) {
      const nearest = nearestRelations(relations, {
        source: FqnRef.flatten(source),
        target: FqnRef.flatten(target),
        title,
      })
      const hint = nearest.length > 0 ? `. Nearest: ${nearest.map(formatRelation).join(', ')}` : ''
      accept(
        'warning',
        `This extend does not match any relation (by source, kind, target, title, and directionality)${hint}`,
        {
          node: el,
        },
      )
    }
  })
}
