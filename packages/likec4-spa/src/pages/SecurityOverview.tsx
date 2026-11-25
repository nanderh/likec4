import type { Fqn } from '@likec4/core/types'
import { buildSecurityRegister, countStatusGroups, SecurityOverview, useLikeC4Model } from '@likec4/diagram'
import { Burger, Button } from '@mantine/core'
import { useDocumentTitle } from '@mantine/hooks'
import { IconArrowLeft } from '@tabler/icons-react'
import { Link, useNavigate } from '@tanstack/react-router'
import { pageTitle } from 'likec4:app-config'
import { useMemo } from 'react'
import { ColorSchemeToggle } from '../components/ColorSchemeToggle'
import { SidebarDrawer } from '../components/sidebar/Drawer'
import { SidebarDrawerOps } from '../components/sidebar/state'
import { Metric, MetricsRow } from '../components/ui/Metric'
import {
  Page,
  PageHeader,
  PageHeading,
  PageLogo,
  PageScroll,
  PageSection,
  PageTitle,
  Toolbar,
  ToolbarSpacer,
} from '../components/ui/Page'
import { EmptyNote } from '../components/ui/Text'
import { useCurrentProject } from '../hooks'

/**
 * All threats and vulnerabilities of the project: summary and register
 */
export function SecurityOverviewPage() {
  const model = useLikeC4Model()
  const { id: projectId, title: projectTitle } = useCurrentProject()
  const navigate = useNavigate()
  const title = `Security · ${projectTitle ?? pageTitle}`
  useDocumentTitle(title)

  const rows = useMemo(() => buildSecurityRegister(model), [model])
  const totals = useMemo(() => ({
    threats: rows.filter(r => r.kind === 'threat').length,
    vulnerabilities: rows.filter(r => r.kind === 'vulnerability').length,
    ...countStatusGroups(rows),
  }), [rows])

  const showInView = (viewId: string, focusOnElement: Fqn) => {
    void navigate({
      to: '/project/$projectId/view/$viewId/',
      params: { projectId, viewId },
      search: { focusOnElement },
    })
  }

  return (
    <Page>
      <SidebarDrawer />
      <PageScroll>
        <PageHeader>
          <PageHeading>
            <Burger size="sm" flex="none" onClick={SidebarDrawerOps.open} aria-label="Toggle navigation" />
            <PageLogo />
            <PageTitle>{title}</PageTitle>
          </PageHeading>
          <MetricsRow>
            <Metric label="Threats" value={totals.threats} size="lg" />
            <Metric label="Vulnerabilities" value={totals.vulnerabilities} size="lg" />
            <Metric label="Unresolved" value={totals.unresolved} size="lg" />
            <Metric label="Risk carried" value={totals.carried} size="lg" />
            <Metric label="Closed" value={totals.closed} size="lg" />
          </MetricsRow>
        </PageHeader>

        <Toolbar role="toolbar" aria-label="Security overview">
          <Button
            component={Link}
            to="/"
            search
            size="xs"
            variant="subtle"
            color="gray"
            leftSection={<IconArrowLeft size={14} />}>
            Overview
          </Button>
          <ToolbarSpacer />
          <ColorSchemeToggle />
        </Toolbar>

        <PageSection as="main">
          {rows.length === 0
            ? <EmptyNote>This project has no threats or vulnerabilities.</EmptyNote>
            : <SecurityOverview rows={rows} onShowInView={showInView} />}
        </PageSection>
      </PageScroll>
    </Page>
  )
}
