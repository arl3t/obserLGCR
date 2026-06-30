/**
 * IncidentManagement.tsx
 * Re-exporta CaseManagementDashboard como IncidentManagementPage
 * para compatibilidad con el router y SocOperations.
 *
 * El código legacy (IncidentManagementPageLegacy) fue eliminado:
 * usar CaseManagementDashboard directamente.
 */

export { CaseManagementDashboard as IncidentManagementPage } from "@/components/case-management/CaseManagementDashboard";
