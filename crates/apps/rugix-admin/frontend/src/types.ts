import type { events, jobs } from "./generated";

export type Tab = "system" | "components" | "apps" | "jobs";

export type Theme = "light" | "dark";

export type JobLog = {
  job?: jobs.Job;
  lines: string[];
  uploadedBytes?: events.UploadProgressEvent["bytes"];
  installProgress?: events.InstallProgressEvent["progress"];
  browserUpload?: { sent: number; total: number };
};
