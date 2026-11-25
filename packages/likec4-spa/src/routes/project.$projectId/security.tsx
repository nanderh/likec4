import { createFileRoute } from '@tanstack/react-router'
import { ErrorComponent } from '../../components/ErrorComponent'
import { SecurityOverviewPage } from '../../pages/SecurityOverview'

export const Route = createFileRoute('/project/$projectId/security')({
  component: SecurityOverviewPage,
  errorComponent: ErrorComponent,
})
