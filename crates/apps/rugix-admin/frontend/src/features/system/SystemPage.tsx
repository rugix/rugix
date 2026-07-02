import { Check, Power, RotateCcw, Trash2, Upload } from "lucide-react";
import type { InstallOptions } from "../../api";
import type { api } from "../../generated";
import { UploadPanel } from "../install/UploadPanel";
import { ActionGroup } from "../../shared/components/ActionGroup";
import { Surface } from "../../shared/components/Surface";
import { confirmAction } from "../../shared/lib/confirm";
import { buttonClass, dangerButtonClass } from "../../shared/styles";
import { StatusCell } from "./StatusCell";

export function SystemPage({
  system,
  onAction,
  onUpload,
  onUrlInstall,
}: {
  system?: api.SystemInfoResponse;
  onAction: (action: string) => void;
  onUpload: (file: File, options: InstallOptions) => void;
  onUrlInstall: (url: string, options: InstallOptions) => void;
}) {
  return (
    <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
      <div className="space-y-5">
        <Surface className="p-0">
          <div className="grid divide-y divide-divider sm:grid-cols-3 sm:divide-x sm:divide-y-0">
            <StatusCell label="Active" value={system?.activeBootGroup ?? "unknown"} />
            <StatusCell label="Default" value={system?.defaultBootGroup ?? "unknown"} />
            <StatusCell label="State" value={system?.stateStatus ?? "unknown"} />
          </div>
        </Surface>

        <UploadPanel
          title="System Update"
          fileLabel="Update bundle"
          icon={<Upload size={18} />}
          system
          allowUrl
          onUpload={onUpload}
          onUrlInstall={onUrlInstall}
        />
      </div>

      <Surface title="System Actions">
        <div className="space-y-4">
          <ActionGroup title="Boot">
            <button className={buttonClass} onClick={() => onAction("commit")}>
              <Check size={16} /> Commit
            </button>
            <button className={buttonClass} onClick={() => onAction("reboot")}>
              <Power size={16} /> Reboot
            </button>
            <button className={buttonClass} onClick={() => onAction("reboot-spare")}>
              <RotateCcw size={16} /> Reboot Spare
            </button>
          </ActionGroup>

          <ActionGroup title="Recovery">
            <button className={dangerButtonClass} onClick={() => confirmAction("Factory reset?") && onAction("factory-reset")}>
              <Trash2 size={16} /> Factory Reset
            </button>
          </ActionGroup>
        </div>
      </Surface>
    </div>
  );
}
