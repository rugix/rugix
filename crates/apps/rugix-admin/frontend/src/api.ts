import type { api, events, jobs } from "./generated";

export class ApiRequestError extends Error {
  status: number;
  code: string;
  details?: unknown;

  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.name = "ApiRequestError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const { headers, ...requestInit } = init ?? {};
  const response = await fetch(url, {
    ...requestInit,
    headers: { Accept: "application/json", ...(headers ?? {}) },
  });
  if (!response.ok) {
    let message = response.statusText;
    let code = "request-failed";
    let details: unknown;
    try {
      const body = (await response.json()) as api.ApiErrorResponse;
      message = body.error.message;
      code = body.error.code;
      details = body.error.details;
    } catch {
      // Keep the HTTP status text.
    }
    throw new ApiRequestError(response.status, code, message, details);
  }
  return (await response.json()) as T;
}

export const AdminApi = {
  health: () => request<api.HealthResponse>("/api/health"),
  systemInfo: () => request<api.SystemInfoResponse>("/api/system/info"),
  components: () => request<api.ComponentsCheckResponse>("/api/components"),
  apps: () => request<api.AppsListResponse>("/api/apps"),
  app: (name: string) => request<api.AppInfoResponse>(`/api/apps/${encodeURIComponent(name)}`),
  jobs: () => request<api.JobsListResponse>("/api/jobs"),
  job: (id: string) => request<api.JobResponse>(`/api/jobs/${encodeURIComponent(id)}`),
  systemAction: (action: string) =>
    request<api.JobResponse>(`/api/system/actions/${encodeURIComponent(action)}`, {
      method: "POST",
    }),
  appAction: (app: string, action: string, query?: Record<string, string | number | undefined>) =>
    request<api.JobResponse>(
      `/api/apps/${encodeURIComponent(app)}/actions/${encodeURIComponent(action)}${queryString(query)}`,
      { method: "POST" },
    ),
};

export function subscribeJob(jobId: string, onEvent: (event: events.AdminEvent) => void) {
  const source = new EventSource(`/api/jobs/${encodeURIComponent(jobId)}/events`);
  source.onmessage = (message) => onEvent(JSON.parse(message.data) as events.AdminEvent);
  source.addEventListener("job-changed", (message) =>
    onEvent(JSON.parse((message as MessageEvent).data) as events.AdminEvent),
  );
  source.addEventListener("job-output", (message) =>
    onEvent(JSON.parse((message as MessageEvent).data) as events.AdminEvent),
  );
  source.addEventListener("upload-progress", (message) =>
    onEvent(JSON.parse((message as MessageEvent).data) as events.AdminEvent),
  );
  source.addEventListener("install-progress", (message) =>
    onEvent(JSON.parse((message as MessageEvent).data) as events.AdminEvent),
  );
  return source;
}

export function uploadSystemUpdate(
  jobId: string,
  file: File,
  options: InstallOptions,
  onProgress: (sent: number, total: number) => void,
) {
  return uploadBundle(`/api/system/update/${encodeURIComponent(jobId)}${installQuery(options)}`, "image", file, onProgress);
}

export function installSystemUpdateFromUrl(jobId: string, url: string, options: InstallOptions) {
  return request<api.JobResponse>(`/api/system/update/${encodeURIComponent(jobId)}/url${installQuery(options)}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  }).then((response) => response.job);
}

export function uploadAppBundle(
  jobId: string,
  file: File,
  options: InstallOptions,
  onProgress: (sent: number, total: number) => void,
) {
  return uploadBundle(`/api/apps/install/${encodeURIComponent(jobId)}${installQuery(options)}`, "bundle", file, onProgress);
}

export type InstallOptions = {
  bundleHash?: string;
  rootCert?: string;
  insecureSkipBundleVerification?: boolean;
  insecureAllowMissingBlockIndex?: boolean;
  reboot?: "yes" | "no" | "set" | "deferred";
  bootGroup?: string;
  keepOverlay?: boolean;
};

function uploadBundle(
  url: string,
  field: string,
  file: File,
  onProgress: (sent: number, total: number) => void,
): Promise<jobs.Job> {
  const form = new FormData();
  form.append(field, file);

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", url);
    xhr.responseType = "text";
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) {
        onProgress(event.loaded, event.total);
      }
    };
    xhr.onload = () => {
      try {
        const body = JSON.parse(xhr.responseText) as api.JobResponse | api.ApiErrorResponse;
        if (xhr.status >= 200 && xhr.status < 300 && "job" in body) {
          resolve(body.job);
        } else if ("error" in body) {
          reject(new ApiRequestError(xhr.status, body.error.code, body.error.message, body.error.details));
        } else {
          reject(new ApiRequestError(xhr.status, "upload-failed", xhr.statusText));
        }
      } catch (error) {
        reject(error);
      }
    };
    xhr.onerror = () => reject(new ApiRequestError(0, "network-error", "upload failed"));
    xhr.send(form);
  });
}

function installQuery(options: InstallOptions) {
  return queryString({
    bundleHash: options.bundleHash,
    rootCert: options.rootCert,
    insecureSkipBundleVerification: options.insecureSkipBundleVerification ? "true" : undefined,
    insecureAllowMissingBlockIndex: options.insecureAllowMissingBlockIndex ? "true" : undefined,
    reboot: options.reboot,
    bootGroup: options.bootGroup,
    keepOverlay: options.keepOverlay ? "true" : undefined,
  });
}

function queryString(query?: Record<string, string | number | undefined>) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined && value !== "") {
      params.set(key, String(value));
    }
  }
  const string = params.toString();
  return string ? `?${string}` : "";
}
