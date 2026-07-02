export const SCHEDULE_INTERVALS = [
  { minutes: 15, label: "Cada 15 minutos" },
  { minutes: 30, label: "Cada 30 minutos" },
  { minutes: 60, label: "Cada hora" },
  { minutes: 120, label: "Cada 2 horas" },
  { minutes: 360, label: "Cada 6 horas" },
  { minutes: 720, label: "Cada 12 horas" },
  { minutes: 1440, label: "Cada 24 horas" },
] as const;

export type ScheduleMode = "off" | "interval" | "cron";

export function scheduleLabel(job: {
  schedule_enabled: boolean;
  schedule_interval_minutes?: number | null;
  schedule_cron?: string | null;
}): string | null {
  if (!job.schedule_enabled) return null;
  if (job.schedule_interval_minutes) {
    const preset = SCHEDULE_INTERVALS.find((i) => i.minutes === job.schedule_interval_minutes);
    return preset?.label ?? `Cada ${job.schedule_interval_minutes} min`;
  }
  if (job.schedule_cron) return `Cron ${job.schedule_cron}`;
  return "Programado";
}

export function intervalToCronHint(minutes: number): string {
  if (minutes >= 1440) return "0 2 * * *";
  if (minutes >= 360) return "0 */6 * * *";
  if (minutes >= 60) return "0 * * * *";
  return `*/${minutes} * * * *`;
}
