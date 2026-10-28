import {
  type Link as LinkData,
  type RiskLevel,
  type SecuritySeverity,
  type SecurityStatus,
  type StrideCategory,
  type Threat,
  type Vulnerability,
  compareSeverity,
  highestSeverity,
  isUnresolvedSecurityStatus,
  RichText,
  StrideCategories,
  StrideLetters,
  StrideProperties,
  StrideTitles,
  threatRisk,
  vulnerabilitySeverity,
} from '@likec4/core/types'
import { css } from '@likec4/styles/css'
import { HStack, styled, VStack } from '@likec4/styles/jsx'
import {
  type MantineColor,
  Anchor,
  Badge,
  Paper,
  Text,
  Tooltip as MantineTooltip,
} from '@mantine/core'
import { useMemo } from 'react'
import { countBy } from 'remeda'
import { Markdown } from '../../base-primitives/Markdown'
import { Link } from '../Link'

const Tooltip = MantineTooltip.withProps({
  color: 'dark',
  fz: 'xs',
  openDelay: 300,
  closeDelay: 100,
  label: '',
  children: null,
  withinPortal: false,
})

export const severityColor = {
  critical: 'red',
  high: 'orange',
  medium: 'yellow',
  low: 'green',
  info: 'gray',
} as const satisfies Record<SecuritySeverity, MantineColor>

export const statusColor = {
  'open': 'red',
  'in-progress': 'blue',
  'mitigated': 'teal',
  'accepted': 'gray',
  'transferred': 'violet',
  'resolved': 'green',
  'false-positive': 'gray',
} as const satisfies Record<SecurityStatus, MantineColor>

const Label = styled('div', {
  base: {
    fontSize: 'xxs',
    fontWeight: 'medium',
    textTransform: 'uppercase',
    letterSpacing: 'caps.sm',
    color: 'text.dimmed',
    userSelect: 'none',
  },
})

const itemId = css({
  fontFamily: 'mono',
  fontSize: 'xs',
  fontWeight: 'semibold',
  whiteSpace: 'nowrap',
})

export function SeverityBadge({ severity, label }: { severity: SecuritySeverity | RiskLevel; label?: string }) {
  return (
    <Badge
      size="sm"
      radius="sm"
      fw={600}
      variant={severity === 'critical' ? 'filled' : 'light'}
      color={severityColor[severity]}
    >
      {label ? `${label} ${severity}` : severity}
    </Badge>
  )
}

export function StatusBadge({ status }: { status: SecurityStatus | null | undefined }) {
  const value = status ?? 'open'
  return (
    <Badge size="sm" radius="sm" fw={500} variant="outline" color={statusColor[value]}>
      {value}
    </Badge>
  )
}

const strideChip = css({
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  width: '[20px]',
  height: '[20px]',
  borderRadius: 'xs',
  fontSize: 'xs',
  fontWeight: 'bold',
  fontFamily: 'mono',
  userSelect: 'none',
  color: 'text.dimmed',
  background: 'surface.sunken',
  opacity: '[0.45]',
  '&[data-active="true"]': {
    opacity: '1',
    color: 'white',
    background: '[var(--mantine-color-violet-6)]',
  },
})

/**
 * Renders S T R I D E letters, highlighting categories of the threat
 */
export function StrideChips({ stride }: { stride: readonly StrideCategory[] }) {
  return (
    <HStack gap="0.5">
      {StrideCategories.map(category => (
        <Tooltip
          key={category}
          label={`${StrideTitles[category]} — violates ${StrideProperties[category].toLowerCase()}`}
        >
          <span className={strideChip} data-active={stride.includes(category)}>
            {StrideLetters[category]}
          </span>
        </Tooltip>
      ))}
    </HStack>
  )
}

function referenceUrl(id: string): string | null {
  let match
  switch (true) {
    case /^CVE-\d{4}-\d+$/i.test(id):
      return `https://nvd.nist.gov/vuln/detail/${id.toUpperCase()}`
    case /^GHSA(-[\w]{4}){3}$/i.test(id):
      return `https://github.com/advisories/${id}`
    case !!(match = /^CWE-(\d+)$/i.exec(id)):
      return `https://cwe.mitre.org/data/definitions/${match[1]}.html`
    default:
      return null
  }
}

function ItemId({ id, links }: { id: string; links: readonly LinkData[] | null | undefined }) {
  const url = links?.length ? null : referenceUrl(id)
  if (url) {
    return (
      <Anchor href={url} target="_blank" rel="noreferrer" className={itemId} onClick={e => e.stopPropagation()}>
        {id}
      </Anchor>
    )
  }
  return <span className={itemId}>{id}</span>
}

function ItemSection({ label, value }: { label: string; value: Vulnerability['description'] }) {
  if (!value) {
    return null
  }
  return (
    <VStack gap="0.5" alignItems="stretch">
      <Label>{label}</Label>
      <Markdown value={RichText.from(value)} fontSize="sm" textScale={0.9} />
    </VStack>
  )
}

function ItemLinks({ links }: { links: readonly LinkData[] | null | undefined }) {
  if (!links || links.length === 0) {
    return null
  }
  return (
    <HStack gap="1" flexWrap="wrap">
      {links.map((link, i) => <Link key={i} size="sm" value={link} />)}
    </HStack>
  )
}

const card = css({
  display: 'flex',
  flexDirection: 'column',
  gap: 'xs',
  '&[data-resolved="true"]': {
    opacity: '0.7',
  },
})

export function VulnerabilityCard({ vulnerability: v }: { vulnerability: Vulnerability }) {
  const severity = vulnerabilitySeverity(v)
  return (
    <Paper withBorder p="sm" radius="sm" className={card} data-resolved={!isUnresolvedSecurityStatus(v.status)}>
      <HStack justify="space-between" alignItems="start" gap="sm" flexWrap="nowrap">
        <VStack gap="0" alignItems="start" minWidth="0">
          <ItemId id={v.id} links={v.links} />
          {v.title && <Text fz="sm" fw={500} lh={1.35}>{v.title}</Text>}
        </VStack>
        <HStack gap="1" flexShrink={0}>
          {severity && <SeverityBadge severity={severity} />}
          {v.cvss != null && (
            <Tooltip label={v.vector ?? 'CVSS base score'}>
              <Badge size="sm" radius="sm" variant="default" fw={600}>CVSS {v.cvss.toFixed(1)}</Badge>
            </Tooltip>
          )}
          <StatusBadge status={v.status} />
        </HStack>
      </HStack>
      {v.cwe && (
        <HStack gap="1">
          <Label>weakness</Label>
          <ItemId id={v.cwe} links={null} />
        </HStack>
      )}
      <ItemSection label="description" value={v.description} />
      <ItemSection label="mitigation" value={v.mitigation} />
      <ItemLinks links={v.links} />
    </Paper>
  )
}

export function ThreatCard({ threat: t }: { threat: Threat }) {
  const risk = threatRisk(t)
  return (
    <Paper withBorder p="sm" radius="sm" className={card} data-resolved={!isUnresolvedSecurityStatus(t.status)}>
      <HStack justify="space-between" alignItems="start" gap="sm" flexWrap="nowrap">
        <VStack gap="0" alignItems="start" minWidth="0">
          <ItemId id={t.id} links={t.links} />
          {t.title && <Text fz="sm" fw={500} lh={1.35}>{t.title}</Text>}
        </VStack>
        <HStack gap="1" flexShrink={0}>
          {risk && <SeverityBadge severity={risk} label="risk" />}
          <StatusBadge status={t.status} />
        </HStack>
      </HStack>
      <HStack gap="md" flexWrap="wrap">
        <StrideChips stride={t.stride} />
        {t.likelihood && (
          <HStack gap="1">
            <Label>likelihood</Label>
            <Text fz="xs" fw={500}>{t.likelihood}</Text>
          </HStack>
        )}
        {t.impact && (
          <HStack gap="1">
            <Label>impact</Label>
            <Text fz="xs" fw={500}>{t.impact}</Text>
          </HStack>
        )}
      </HStack>
      <ItemSection label="description" value={t.description} />
      <ItemSection label="mitigation" value={t.mitigation} />
      <ItemLinks links={t.links} />
    </Paper>
  )
}

const resolvedRank = (status: SecurityStatus | null | undefined) => isUnresolvedSecurityStatus(status) ? 0 : 1

/**
 * Sorts vulnerabilities: unresolved first, then by severity
 */
export function sortVulnerabilities(vulnerabilities: ReadonlyArray<Vulnerability>): Vulnerability[] {
  return [...vulnerabilities].sort((a, b) =>
    resolvedRank(a.status) - resolvedRank(b.status)
    || compareSeverity(vulnerabilitySeverity(a), vulnerabilitySeverity(b))
  )
}

/**
 * Sorts threats: unresolved first, then by risk
 */
export function sortThreats(threats: ReadonlyArray<Threat>): Threat[] {
  return [...threats].sort((a, b) =>
    resolvedRank(a.status) - resolvedRank(b.status)
    || compareSeverity(threatRisk(a), threatRisk(b))
  )
}

const summaryCell = css({
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'center',
  gap: '0.5',
  padding: 'xs',
  borderRadius: 'sm',
  background: 'surface.sunken',
  minWidth: '0',
})

/**
 * Overview of threats by STRIDE category
 */
export function StrideSummary({ threats }: { threats: ReadonlyArray<Threat> }) {
  const byCategory = useMemo(() =>
    StrideCategories.map(category => {
      const matching = threats.filter(t => t.stride.includes(category))
      const unresolved = matching.filter(t => isUnresolvedSecurityStatus(t.status))
      return {
        category,
        total: matching.length,
        unresolved: unresolved.length,
        risk: highestSeverity(unresolved.map(threatRisk)),
      }
    }), [threats])

  return (
    <div className={css({ display: 'grid', gridTemplateColumns: 'repeat(6, minmax(0, 1fr))', gap: 'xs' })}>
      {byCategory.map(({ category, total, unresolved, risk }) => (
        <Tooltip
          key={category}
          label={`${StrideTitles[category]}: ${unresolved} unresolved of ${total}`}
        >
          <div className={summaryCell}>
            <Text fz="lg" fw={700} ff="monospace" lh={1}>{StrideLetters[category]}</Text>
            <Text fz={10} c="dimmed" ta="center" lh={1.2} truncate="end" maw="100%">
              {StrideTitles[category]}
            </Text>
            {total > 0
              ? (
                <Badge
                  size="sm"
                  radius="sm"
                  variant={risk === 'critical' ? 'filled' : 'light'}
                  color={risk ? severityColor[risk] : 'gray'}>
                  {unresolved}/{total}
                </Badge>
              )
              : <Badge size="sm" radius="sm" variant="transparent" color="gray">—</Badge>}
          </div>
        </Tooltip>
      ))}
    </div>
  )
}

/**
 * Number of unresolved vulnerabilities by severity
 */
export function VulnerabilitySummary({ vulnerabilities }: { vulnerabilities: ReadonlyArray<Vulnerability> }) {
  const counts = useMemo(() =>
    countBy(
      vulnerabilities.filter(v => isUnresolvedSecurityStatus(v.status)),
      v => vulnerabilitySeverity(v) ?? 'unknown',
    ), [vulnerabilities])
  const unresolved = Object.values(counts).reduce((a, b) => a + b, 0)
  return (
    <HStack gap="xs" flexWrap="wrap">
      <Text fz="xs" c="dimmed">
        {unresolved} unresolved of {vulnerabilities.length}
      </Text>
      {(['critical', 'high', 'medium', 'low', 'info'] as const).map(severity =>
        counts[severity]
          ? <SeverityBadge key={severity} severity={severity} label={String(counts[severity])} />
          : null
      )}
    </HStack>
  )
}

/**
 * Compact rows of threats and vulnerabilities, for popovers
 */
export function SecurityCompactList({
  threats,
  vulnerabilities,
}: {
  threats: ReadonlyArray<Threat>
  vulnerabilities: ReadonlyArray<Vulnerability>
}) {
  return (
    <VStack gap="1" alignItems="stretch">
      {sortThreats(threats).map((t, i) => {
        const risk = threatRisk(t)
        return (
          <HStack
            key={`t-${t.id}-${i}`}
            gap="xs"
            flexWrap="nowrap"
            opacity={isUnresolvedSecurityStatus(t.status) ? '1' : '[0.6]'}>
            <StrideChips stride={t.stride} />
            <span className={itemId}>{t.id}</span>
            <Text fz="xs" truncate="end" flex={1} miw={0}>{t.title}</Text>
            {risk && <SeverityBadge severity={risk} />}
          </HStack>
        )
      })}
      {sortVulnerabilities(vulnerabilities).map((v, i) => {
        const severity = vulnerabilitySeverity(v)
        return (
          <HStack
            key={`v-${v.id}-${i}`}
            gap="xs"
            flexWrap="nowrap"
            opacity={isUnresolvedSecurityStatus(v.status) ? '1' : '[0.6]'}>
            <ItemId id={v.id} links={v.links} />
            <Text fz="xs" truncate="end" flex={1} miw={0}>{v.title}</Text>
            {severity && <SeverityBadge severity={severity} />}
          </HStack>
        )
      })}
    </VStack>
  )
}
