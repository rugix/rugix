import { useEffect, useMemo, useState } from "react";
import {
  AdminApi,
  installSystemUpdateFromUrl,
  type InstallOptions,
  subscribeJob,
  uploadAppBundle,
  uploadSystemUpdate,
} from "./api";
import { AppsPage } from "./features/apps/AppsPage";
import { ComponentsPage } from "./features/components/ComponentsPage";
import { ActiveOperation } from "./features/jobs/ActiveOperation";
import { JobsPage } from "./features/jobs/JobsPage";
import { DemoDisclaimer } from "./features/shell/DemoDisclaimer";
import { PageTitle } from "./features/shell/PageTitle";
import { TopNav } from "./features/shell/TopNav";
import { SystemPage } from "./features/system/SystemPage";
import type { api, jobs } from "./generated";
import { ErrorBanner } from "./shared/components/ErrorBanner";
import { errorMessage } from "./shared/lib/errors";
import { createJobId } from "./shared/lib/ids";
import { applyEvent, isTerminal, updateBrowserProgress } from "./shared/lib/jobEvents";
import { initialTheme } from "./shared/lib/theme";
import type { JobLog, Tab, Theme } from "./types";

export function App() {
  const [tab, setTab] = useState<Tab>("system");
  const [system, setSystem] = useState<api.SystemInfoResponse>();
  const [components, setComponents] = useState<api.ComponentsCheckResponse>();
  const [appsList, setAppsList] = useState<api.AppSummary[]>([]);
  const [selectedApp, setSelectedApp] = useState<string>();
  const [appInfo, setAppInfo] = useState<api.AppInfoResponse>();
  const [jobsList, setJobsList] = useState<jobs.Job[]>([]);
  const [logs, setLogs] = useState<Record<string, JobLog>>({});
  const [activeJobId, setActiveJobId] = useState<string>();
  const [error, setError] = useState<string>();
  const [theme, setTheme] = useState<Theme>(() => initialTheme());

  const activeLog = activeJobId ? logs[activeJobId] : undefined;
  const activeJob = activeLog?.job ?? jobsList.find((job) => job.id === activeJobId);
  const pendingJobs = jobsList.filter((job) => job.status.status === "queued" || job.status.status === "running");
  const selectedSummary = useMemo(
    () => appsList.find((app) => app.name === selectedApp),
    [appsList, selectedApp],
  );

  async function refresh() {
    setError(undefined);
    const [systemInfo, componentReport, appList, jobList] = await Promise.allSettled([
      AdminApi.systemInfo(),
      AdminApi.components(),
      AdminApi.apps(),
      AdminApi.jobs(),
    ]);
    if (systemInfo.status === "fulfilled") setSystem(systemInfo.value);
    if (componentReport.status === "fulfilled") setComponents(componentReport.value);
    if (appList.status === "fulfilled") setAppsList(appList.value.apps);
    if (jobList.status === "fulfilled") setJobsList(jobList.value.jobs);
    const firstError = [systemInfo, componentReport, appList, jobList].find((result) => result.status === "rejected");
    if (firstError?.status === "rejected") setError(errorMessage(firstError.reason));
  }

  async function refreshApp(app = selectedApp) {
    if (!app) {
      setAppInfo(undefined);
      return;
    }
    try {
      setAppInfo(await AdminApi.app(app));
    } catch (error) {
      setError(errorMessage(error));
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  useEffect(() => {
    if (appsList.length === 0) {
      setSelectedApp(undefined);
      return;
    }
    if (!selectedApp || !appsList.some((app) => app.name === selectedApp)) {
      setSelectedApp(appsList[0].name);
    }
  }, [appsList, selectedApp]);

  useEffect(() => {
    void refreshApp();
  }, [selectedApp]);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
    localStorage.setItem("rugix-admin-theme", theme);
  }, [theme]);

  function watchJob(jobId: string) {
    setActiveJobId(jobId);
    const source = subscribeJob(jobId, (event) => {
      setLogs((current) => applyEvent(current, event));
      if (event.type === "job-changed" && isTerminal(event.job.status)) {
        void refresh();
        void refreshApp();
        source.close();
      }
    });
  }

  function openJob(jobId: string) {
    if (jobId === activeJobId && logs[jobId]) return;
    watchJob(jobId);
  }

  async function runSystemAction(action: string) {
    try {
      const response = await AdminApi.systemAction(action);
      setLogs((current) => ({ ...current, [response.job.id]: { job: response.job, lines: [] } }));
      watchJob(response.job.id);
    } catch (error) {
      setError(errorMessage(error));
    }
  }

  async function runAppAction(action: string, query?: Record<string, string | number | undefined>) {
    if (!selectedApp) return;
    try {
      const response = await AdminApi.appAction(selectedApp, action, query);
      setLogs((current) => ({ ...current, [response.job.id]: { job: response.job, lines: [] } }));
      watchJob(response.job.id);
    } catch (error) {
      setError(errorMessage(error));
    }
  }

  async function upload(kind: "system" | "app", file: File, options: InstallOptions) {
    const jobId = createJobId();
    setLogs((current) => ({ ...current, [jobId]: { lines: [] } }));
    watchJob(jobId);
    try {
      const job =
        kind === "system"
          ? await uploadSystemUpdate(jobId, file, options, (sent, total) =>
              setLogs((current) => updateBrowserProgress(current, jobId, sent, total)),
            )
          : await uploadAppBundle(jobId, file, options, (sent, total) =>
              setLogs((current) => updateBrowserProgress(current, jobId, sent, total)),
            );
      setLogs((current) => ({ ...current, [jobId]: { ...(current[jobId] ?? { lines: [] }), job } }));
    } catch (error) {
      setError(errorMessage(error));
    }
  }

  async function installSystemUrl(url: string, options: InstallOptions) {
    const jobId = createJobId();
    setLogs((current) => ({ ...current, [jobId]: { lines: [] } }));
    watchJob(jobId);
    try {
      const job = await installSystemUpdateFromUrl(jobId, url, options);
      setLogs((current) => ({ ...current, [jobId]: { ...(current[jobId] ?? { lines: [] }), job } }));
    } catch (error) {
      setError(errorMessage(error));
    }
  }

  return (
    <div className="mesh-gradient min-h-screen bg-elevation-0 text-foreground">
      <TopNav
        tab={tab}
        theme={theme}
        pendingJobs={pendingJobs}
        onTabChange={setTab}
        onThemeChange={setTheme}
        onRefresh={() => void refresh()}
      />

      <main className="mx-auto max-w-[1520px] space-y-5 px-4 py-5 sm:px-6 lg:px-8">
        <DemoDisclaimer />
        <PageTitle tab={tab} />
        {error && <ErrorBanner message={error} />}
        {activeJobId && (
          <ActiveOperation
            jobId={activeJobId}
            job={activeJob}
            log={activeLog}
            onOpen={() => {
              setTab("jobs");
              openJob(activeJobId);
            }}
          />
        )}

        {tab === "system" && (
          <SystemPage
            system={system}
            onAction={(action) => void runSystemAction(action)}
            onUpload={(file, options) => void upload("system", file, options)}
            onUrlInstall={(url, options) => void installSystemUrl(url, options)}
          />
        )}
        {tab === "components" && <ComponentsPage report={components} />}
        {tab === "apps" && (
          <AppsPage
            apps={appsList}
            selected={selectedSummary}
            info={appInfo}
            onSelect={setSelectedApp}
            onUpload={(file, options) => void upload("app", file, options)}
            onAction={(action, query) => void runAppAction(action, query)}
          />
        )}
        {tab === "jobs" && (
          <JobsPage
            jobs={jobsList}
            selected={activeJobId}
            log={activeLog}
            selectedJob={activeJob}
            onSelect={openJob}
          />
        )}
      </main>
    </div>
  );
}
