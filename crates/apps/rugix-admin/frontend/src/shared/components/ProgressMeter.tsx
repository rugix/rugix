export function ProgressMeter({
  label = "Upload",
  percent,
  fallback,
}: {
  label?: string;
  percent?: number;
  fallback?: string;
}) {
  if (percent === undefined && !fallback) return null;
  const boundedPercent = percent === undefined ? undefined : Math.min(Math.max(percent, 0), 100);
  return (
    <div>
      <div className="mb-1 flex justify-between text-xs text-foreground-muted">
        <span>{label}</span>
        <span>{boundedPercent === undefined ? fallback : `${boundedPercent}%`}</span>
      </div>
      {boundedPercent !== undefined && (
        <div className="h-1.5 overflow-hidden rounded-full bg-elevation-3">
          <div className="h-full bg-primary" style={{ width: `${boundedPercent}%` }} />
        </div>
      )}
    </div>
  );
}
