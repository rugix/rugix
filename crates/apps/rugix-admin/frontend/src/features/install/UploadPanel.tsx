import { ChevronDown, Link, Upload } from "lucide-react";
import { useState, type ReactNode } from "react";
import type { InstallOptions } from "../../api";
import { Input } from "../../shared/components/Input";
import { Surface } from "../../shared/components/Surface";
import { formatBytes } from "../../shared/lib/format";
import { buttonClass, fieldClass, primaryButtonClass } from "../../shared/styles";

export function UploadPanel({
  title,
  fileLabel,
  icon,
  system,
  allowUrl,
  onUpload,
  onUrlInstall,
}: {
  title: string;
  fileLabel: string;
  icon: ReactNode;
  system?: boolean;
  allowUrl?: boolean;
  onUpload: (file: File, options: InstallOptions) => void;
  onUrlInstall?: (url: string, options: InstallOptions) => void;
}) {
  const [source, setSource] = useState<"file" | "url">("file");
  const [file, setFile] = useState<File>();
  const [url, setUrl] = useState("");
  const [bundleHash, setBundleHash] = useState("");
  const [rootCert, setRootCert] = useState("");
  const [insecure, setInsecure] = useState(false);
  const [allowMissingIndex, setAllowMissingIndex] = useState(false);
  const [reboot, setReboot] = useState<InstallOptions["reboot"]>("no");
  const options = {
    bundleHash,
    rootCert,
    insecureSkipBundleVerification: insecure,
    insecureAllowMissingBlockIndex: allowMissingIndex,
    reboot: system ? reboot : undefined,
  };
  const canInstall = source === "file" ? !!file : !!url.trim();

  return (
    <Surface title={title} icon={icon}>
      <div className="space-y-4">
        {allowUrl && (
          <div className="grid grid-cols-2 gap-2">
            <button
              type="button"
              className={source === "file" ? primaryButtonClass : buttonClass}
              onClick={() => setSource("file")}
            >
              <Upload size={16} /> File
            </button>
            <button
              type="button"
              className={source === "url" ? primaryButtonClass : buttonClass}
              onClick={() => setSource("url")}
            >
              <Link size={16} /> URL
            </button>
          </div>
        )}

        {source === "file" ? (
          <label className="block">
            <input className="sr-only" type="file" onChange={(event) => setFile(event.target.files?.[0])} />
            <span className="flex min-h-24 cursor-pointer items-center justify-between gap-4 rounded-lg border border-dashed border-frame bg-elevation-0 px-4 py-3 transition hover:border-primary hover:bg-primary-muted">
              <span className="min-w-0">
                <span className="block text-sm font-medium text-foreground">{file?.name ?? fileLabel}</span>
                <span className="mt-1 block truncate text-xs text-foreground-muted">{file ? formatBytes(file.size) : "No file selected"}</span>
              </span>
              <span className="inline-flex h-9 shrink-0 items-center justify-center gap-2 rounded-md bg-primary px-3 text-sm font-medium text-primary-content">
                <Upload size={16} /> Choose
              </span>
            </span>
          </label>
        ) : (
          <label className="block">
            <span className="mb-1 block text-sm font-medium text-foreground-muted">Update URL</span>
            <span className="flex items-center gap-2">
              <input
                className={fieldClass}
                type="url"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                placeholder="https://example.com/update.rugixb"
              />
            </span>
          </label>
        )}

        <details className="group border-t border-divider pt-3">
          <summary className="flex cursor-pointer list-none items-center justify-between text-sm font-medium text-foreground-muted transition hover:text-foreground">
            Advanced
            <ChevronDown size={16} className="transition group-open:rotate-180" />
          </summary>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <Input label="Bundle hash" value={bundleHash} onChange={setBundleHash} />
            <Input label="Root certificate" value={rootCert} onChange={setRootCert} />
            {system && (
              <label className="block md:col-span-2">
                <span className="mb-1 block text-sm font-medium text-foreground-muted">Reboot</span>
                <select
                  className={fieldClass}
                  value={reboot}
                  onChange={(event) => setReboot(event.target.value as InstallOptions["reboot"])}
                >
                  <option value="no">No</option>
                  <option value="yes">Yes</option>
                  <option value="set">Set</option>
                  <option value="deferred">Deferred</option>
                </select>
              </label>
            )}
            <label className="inline-flex items-center gap-2 text-sm text-foreground-muted">
              <input className="size-4 accent-primary" type="checkbox" checked={insecure} onChange={(event) => setInsecure(event.target.checked)} />
              Skip verification
            </label>
            <label className="inline-flex items-center gap-2 text-sm text-foreground-muted">
              <input className="size-4 accent-primary" type="checkbox" checked={allowMissingIndex} onChange={(event) => setAllowMissingIndex(event.target.checked)} />
              Allow missing index
            </label>
          </div>
        </details>

        <div className="flex justify-end">
          <button
            className={primaryButtonClass}
            disabled={!canInstall}
            onClick={() => {
              if (source === "file" && file) {
                onUpload(file, options);
              } else if (source === "url") {
                onUrlInstall?.(url.trim(), options);
              }
            }}
          >
            <Upload size={16} /> Install
          </button>
        </div>
      </div>
    </Surface>
  );
}
