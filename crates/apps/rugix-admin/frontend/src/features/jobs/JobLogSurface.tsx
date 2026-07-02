import { Terminal } from "lucide-react";
import type { jobs } from "../../generated";
import { EmptyState } from "../../shared/components/EmptyState";
import { ProgressMeter } from "../../shared/components/ProgressMeter";
import { Surface } from "../../shared/components/Surface";
import { formatBytes } from "../../shared/lib/format";
import { jobProgress, progressLabel } from "../../shared/lib/jobEvents";
import { JobStatusBadge } from "../../shared/status/JobStatusBadge";
import type { JobLog } from "../../types";

export function JobLogSurface({ jobId, job, log }: { jobId?: string; job?: jobs.Job; log?: JobLog }) {
  const progressPercent = jobProgress(log);
  return (
    <Surface title="Job Log" icon={<Terminal size={18} />} action={job && <JobStatusBadge status={job.status} />}>
      {jobId ? (
        <div className="space-y-4">
          <div className="min-w-0">
            <div className="truncate text-sm font-medium">{job?.title ?? jobId}</div>
            <div className="mt-1 truncate font-mono text-xs text-foreground-muted">{jobId}</div>
          </div>
          <ProgressMeter label={progressLabel(log)} percent={progressPercent} fallback={log?.uploadedBytes ? `${formatBytes(Number(log.uploadedBytes))} uploaded` : undefined} />
          <pre className="h-[min(58vh,560px)] overflow-auto rounded-md border border-divider bg-elevation-0 p-3 font-mono text-xs leading-5 text-foreground">
            {(log?.lines.length ? log.lines : ["No output."]).join("\n")}
          </pre>
        </div>
      ) : (
        <EmptyState label="Select a job." />
      )}
    </Surface>
  );
}
