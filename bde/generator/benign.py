"""Normal activity: the background noise, and the "benign twins".

A **benign twin** is normal work that looks like one step of an attack: an
admin's PowerShell, a certutil download of a certificate revocation list, a
remote-management agent that sends encoded PowerShell, an admin using WMI to
run gpupdate on a server. Single-event rules fire on some of these (that is
realistic), and the correlation layer (phase 4) has to tell them apart from
the real chains. Every twin carries meta["twin"] naming the chain it imitates,
so the evaluation (phase 5) can report which twins caused false alarms.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from .catalog import (
    BENIGN_SITES,
    CRL_SITE,
    INTRANET_HOST,
    INTRANET_IP,
    MAIL_HOST,
    MAIL_IP,
    RMM_B64,
    RMM_SITE,
    SYSTEM_USER,
    TEAMS_SITE,
    UPDATE_SITE,
    binary,
    qualified,
)
from .world import Host, Meta, Proc, World

UPPER_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def benign(activity: str, twin: str | None = None) -> Meta:
    meta: Meta = {"label": "benign", "activity": activity}
    if twin:
        meta["twin"] = twin
    return meta


def _app(w: World, host: Host, key: str, name: str, t: datetime, meta: Meta) -> Proc:
    """A long-running app on `host`, started from Explorer the first time it's needed."""
    proc = host.procs.get(key)
    if proc is None:
        proc = w.spawn(host.procs["explorer"], name, f'"{binary(name)[0]}"', t, meta)
        host.procs[key] = proc
    return proc


# --- everyday background ------------------------------------------------------


def browse(w: World, host: Host, t: datetime) -> None:
    meta = benign("web-browsing")
    edge = _app(w, host, "edge", "msedge.exe", t, meta)
    for _ in range(w.rand.int_between(1, 3)):
        t += w.rand.seconds(0.5, 20)
        w.lookup_and_connect(edge, t, w.rand.choice(BENIGN_SITES), 443, meta)


def email(w: World, host: Host, t: datetime) -> None:
    meta = benign("email")
    outlook = host.procs["outlook"]
    w.connect(outlook, t, MAIL_IP, 443, meta, dest_name=MAIL_HOST)
    if w.rand.chance(0.3):  # twin of chain 1's first steps: save and open an attachment
        meta = benign("email-attachment", twin="chain-1")
        doc = w.rand.choice(["Agenda.docx", "Budget_2027.xlsx", "Minutes.docx", "Price_list.xlsx", "Onboarding.docx"])
        folder = w.rand.word(8, UPPER_ALNUM)
        path = f"C:\\Users\\{host.user}\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\{folder}\\{doc}"
        t += w.rand.seconds(0.3, 2)
        w.create_file(outlook, t, path, meta)
        t += w.rand.seconds(5, 90)
        app = "WINWORD.EXE" if doc.endswith(".docx") else "EXCEL.EXE"
        w.spawn(outlook, app, f'"{binary(app)[0]}" /n "{path}" /o ""', t, meta)


def office_work(w: World, host: Host, t: datetime) -> None:
    meta = benign("office-work")
    app = w.rand.choice(["WINWORD.EXE", "EXCEL.EXE"])
    doc = w.rand.choice(["Report", "Notes", "Plan", "Forecast", "Timesheet"]) + (
        ".docx" if app == "WINWORD.EXE" else ".xlsx"
    )
    path = f"C:\\Users\\{host.user}\\Documents\\{doc}"
    proc = w.spawn(host.procs["explorer"], app, f'"{binary(app)[0]}" /n "{path}"', t, meta)
    t += w.rand.seconds(1, 4)
    w.create_file(proc, t, f"C:\\Users\\{host.user}\\Documents\\~${doc[2:]}", meta)
    if w.rand.chance(0.2):  # printing starts a helper process: Office child, but harmless
        t += w.rand.seconds(30, 300)
        w.spawn(proc, "splwow64.exe", "C:\\Windows\\splwow64.exe 12288", t, benign("printing", twin="chain-1"))


def teams(w: World, host: Host, t: datetime) -> None:
    meta = benign("chat")
    proc = _app(w, host, "teams", "ms-teams.exe", t, meta)
    w.lookup_and_connect(proc, t + w.rand.seconds(0.2, 3), TEAMS_SITE, 443, meta)


def notepad(w: World, host: Host, t: datetime) -> None:
    name = w.rand.choice(["todo.txt", "notes.txt", "meeting.txt"])
    w.spawn(host.procs["explorer"], "notepad.exe",
            f'"C:\\Windows\\system32\\NOTEPAD.EXE" C:\\Users\\{host.user}\\Desktop\\{name}', t, benign("notes"))


def windows_update(w: World, host: Host, t: datetime) -> None:
    w.lookup_and_connect(host.procs["svc_wu"], t, UPDATE_SITE, 443, benign("windows-update"))


def scheduled_task(w: World, host: Host, t: datetime) -> None:
    w.spawn(host.procs["svc_netsvcs"], "taskhostw.exe", "taskhostw.exe -RegisterDevice -ProtectionStateChanged", t,
            benign("scheduled-task"))


def rmm_check_in(w: World, host: Host, t: datetime) -> None:
    w.lookup_and_connect(host.procs["rmm"], t, RMM_SITE, 443, benign("remote-management"))


def file_share(w: World, host: Host, t: datetime, server: Host) -> None:
    """The user opens a file share: SMB from the workstation, a network logon on the server."""
    meta = benign("file-share")
    w.connect(host.procs["system"], t, server.ip, 445, meta, dest_name=server.name)
    t += w.rand.seconds(0.01, 0.1)
    w.logon(server, t, host.user or "svc_backup", 3, meta, source_ip=host.ip)
    w.accept(server.procs["system"], t + w.rand.seconds(0.001, 0.02), host.ip, 445, meta)


def unlock(w: World, host: Host, t: datetime) -> None:
    w.logon(host, t, host.user or "adm-adavis", 7, benign("screen-unlock"), source_ip="127.0.0.1",
            workstation=host.short)


def server_job(w: World, host: Host, t: datetime) -> None:
    """A nightly-style sync job that happens to run during the day."""
    meta = benign("server-job")
    cmd = w.spawn(host.procs["svc_netsvcs"], "cmd.exe", 'C:\\Windows\\system32\\cmd.exe /c "C:\\Scripts\\sync-reports.cmd"',
                  t, meta)
    w.spawn(cmd, "robocopy.exe", 'robocopy  "D:\\Reports" "\\\\SRV-FILE-01\\reports$" /MIR /R:1 /W:1',
            t + w.rand.seconds(0.1, 0.5), meta)


# --- benign twins (each scheduled explicitly, see scenario.py) ----------------


def twin_admin_script(w: World, host: Host, t: datetime) -> None:
    """IT runs an inventory script: PowerShell with -ExecutionPolicy Bypass, but from Explorer."""
    meta = benign("admin-script", twin="chain-1")
    ps = w.spawn(host.procs["explorer"], "powershell.exe",
                 "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\IT\\Scripts\\Get-Inventory.ps1", t, meta)
    w.connect(ps, t + w.rand.seconds(0.5, 2), INTRANET_IP, 443, meta, dest_name=INTRANET_HOST)


def twin_rmm_encoded(w: World, host: Host, t: datetime) -> None:
    """A remote-management agent runs an encoded PowerShell command, as many real ones do."""
    meta = benign("remote-management-script", twin="chain-1")
    w.spawn(host.procs["rmm"], "powershell.exe",
            f"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {RMM_B64}", t, meta)


def twin_onedrive_run_key(w: World, host: Host, t: datetime) -> None:
    """OneDrive registers itself to start at logon: a Run key, set by a normal program."""
    meta = benign("app-autostart", twin="chain-1")
    exe = f"C:\\Users\\{host.user}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe"
    proc = w.spawn(host.procs["explorer"], "OneDrive.exe", f'"{exe}" /background', t, meta, image=exe)
    w.set_registry(proc, t + w.rand.seconds(1, 5), w.run_key(host.user or "adavis", "OneDrive"),
                   f'"{exe}" /background', meta)


def twin_certutil_hash(w: World, host: Host, t: datetime) -> None:
    """An admin checks a download's hash with certutil."""
    meta = benign("admin-certutil", twin="chain-2")
    cmd = w.spawn(host.procs["explorer"], "cmd.exe", '"C:\\Windows\\system32\\cmd.exe" ', t, meta)
    w.spawn(cmd, "certutil.exe", f"certutil  -hashfile C:\\Users\\{host.user}\\Downloads\\setup-7.2.1.exe SHA256",
            t + w.rand.seconds(5, 40), meta)


def twin_certutil_crl(w: World, host: Host, t: datetime) -> None:
    """An admin fetches a certificate revocation list with certutil -urlcache.

    Rare but real, and a single-event rule for "certutil downloads something"
    fires on it. Nothing follows it: no decode, no rundll32.
    """
    meta = benign("admin-certutil-download", twin="chain-2")
    name, ip = CRL_SITE
    ps = w.spawn(host.procs["explorer"], "powershell.exe", "powershell.exe", t, meta)
    t += w.rand.seconds(10, 60)
    cu = w.spawn(ps, "certutil.exe",
                 f"certutil.exe -urlcache -f http://{name}/pki/IssuingCA.crl C:\\IT\\pki\\IssuingCA.crl", t, meta)
    t = w.lookup_and_connect(cu, t + w.rand.seconds(0.05, 0.2), CRL_SITE, 80, meta)
    w.create_file(cu, t + w.rand.seconds(0.2, 1), "C:\\IT\\pki\\IssuingCA.crl", meta)


def twin_rundll32_control_panel(w: World, host: Host, t: datetime) -> None:
    """Opening a Control Panel page runs rundll32 with a system DLL."""
    meta = benign("control-panel", twin="chain-2")
    w.spawn(host.procs["explorer"], "rundll32.exe",
            '"C:\\Windows\\system32\\rundll32.exe" C:\\Windows\\system32\\shell32.dll,Control_RunDLL desk.cpl', t, meta)


def twin_logon_script(w: World, host: Host, t: datetime) -> None:
    """The user logs on again; the domain logon script (a .vbs) maps a drive."""
    meta = benign("logon-script", twin="chain-2")
    user = qualified(host.user or "adavis")
    w.logon(host, t, host.user or "adavis", 2, meta, source_ip="127.0.0.1", workstation=host.short)
    t += w.rand.seconds(1, 3)
    userinit = w.spawn(host.procs["winlogon"], "userinit.exe", "C:\\Windows\\system32\\userinit.exe", t, meta, user=user)
    t += w.rand.seconds(0.2, 1)
    host.procs["explorer"] = w.spawn(userinit, "explorer.exe", "C:\\Windows\\Explorer.EXE", t, meta)
    ws = w.spawn(userinit, "wscript.exe", '"C:\\Windows\\System32\\WScript.exe" \\\\corp.example\\NETLOGON\\logon.vbs',
                 t + w.rand.seconds(0.1, 0.5), meta)
    w.spawn(ws, "net.exe", f'"C:\\Windows\\System32\\net.exe" use H: \\\\SRV-FILE-01\\home$\\{host.user} /persistent:no',
            t + w.rand.seconds(0.6, 2), meta)


def twin_admin_discovery(w: World, host: Host, t: datetime) -> None:
    """An admin checks group membership by hand: the same commands an attacker runs."""
    meta = benign("admin-discovery", twin="chain-3")
    ps = w.spawn(host.procs["explorer"], "powershell.exe",
                 '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" ', t, meta)
    t += w.rand.seconds(20, 90)
    w.spawn(ps, "whoami.exe", '"C:\\Windows\\system32\\whoami.exe" /groups', t, meta)
    t += w.rand.seconds(20, 120)
    net = w.spawn(ps, "net.exe", '"C:\\Windows\\system32\\net.exe" group "Domain Admins" /domain', t, meta)
    w.spawn(net, "net1.exe", 'C:\\Windows\\system32\\net1  group "Domain Admins" /domain', t + w.rand.seconds(0.01, 0.05),
            meta)


def twin_remote_gpupdate(w: World, host: Host, t: datetime, target: Host) -> None:
    """An admin uses WMI (CIM) to run gpupdate on a server: chain 3's mechanism, for a normal reason."""
    meta = benign("remote-admin-wmi", twin="chain-3")
    account = host.user or "adm-adavis"
    ps = w.spawn(host.procs["explorer"], "powershell.exe",
                 f'powershell.exe -NoProfile -Command "Invoke-CimMethod -ComputerName {target.short} '
                 "-ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='cmd.exe /c gpupdate /force'}\"",
                 t, meta)
    t += w.rand.seconds(0.5, 1.5)
    w.connect(ps, t, target.ip, 5985, meta, dest_name=target.name)
    t += w.rand.seconds(0.05, 0.2)
    w.logon(target, t, account, 3, meta, source_ip=host.ip)
    w.accept(target.procs["system"], t + w.rand.seconds(0.001, 0.02), host.ip, 5985, meta)
    t += w.rand.seconds(0.3, 1)
    cmd = w.spawn(target.procs["wmiprvse"], "cmd.exe", "cmd.exe /c gpupdate /force", t, meta, user=qualified(account),
                  cwd="C:\\Windows\\system32\\")
    w.spawn(cmd, "gpupdate.exe", "gpupdate  /force", t + w.rand.seconds(0.05, 0.3), meta)


def twin_wmi_management_script(w: World, host: Host, t: datetime) -> None:
    """A management agent asks WMI to run an encoded PowerShell script on this server.

    WmiPrvSE.exe starting a hidden, encoded PowerShell is exactly how chain 3
    begins, and chain 3's rule needs only two steps. So this twin is a known
    false positive: docs/phase-5-evaluation.md discusses how to fix it.
    """
    meta = benign("management-wmi-script", twin="chain-3")
    w.spawn(host.procs["wmiprvse"], "powershell.exe",
            f"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {RMM_B64}", t, meta,
            user=SYSTEM_USER, cwd="C:\\Windows\\system32\\")


def twin_backup_admin(w: World, host: Host, t: datetime, source: Host) -> None:
    """A backup admin RDPs to a server and *checks* shadow copies, backups and logs (reads, not deletes)."""
    meta = benign("backup-check", twin="chain-4")
    account = source.user or "adm-adavis"
    w.logon(host, t, account, 10, meta, source_ip=source.ip, workstation=source.short)
    t += w.rand.seconds(3, 8)
    userinit = w.spawn(host.procs["winlogon"], "userinit.exe", "C:\\Windows\\system32\\userinit.exe", t, meta,
                       user=qualified(account))
    explorer = w.spawn(userinit, "explorer.exe", "C:\\Windows\\Explorer.EXE", t + w.rand.seconds(0.2, 1), meta)
    t += w.rand.seconds(20, 60)
    cmd = w.spawn(explorer, "cmd.exe", '"C:\\Windows\\system32\\cmd.exe" ', t, meta)
    for name, command in w.rand.shuffled([
        ("vssadmin.exe", "vssadmin  list shadows"),
        ("wbadmin.exe", "wbadmin  get versions"),
        ("wevtutil.exe", "wevtutil  qe System /c:20 /rd:true /f:text"),
        ("powershell.exe", 'powershell.exe -NoProfile -Command "Get-MpComputerStatus"'),
    ]):
        t += w.rand.seconds(5, 40)
        w.spawn(cmd, name, command, t, meta)


# --- which background activities each kind of host does ---------------------

Activity = Callable[[World, Host, datetime], None]

BACKGROUND: dict[str, list[tuple[Activity, float]]] = {
    "workstation": [(browse, 5), (email, 4), (office_work, 3), (teams, 3), (notepad, 1), (windows_update, 1),
                    (scheduled_task, 1), (rmm_check_in, 1), (unlock, 1)],
    "jump": [(windows_update, 1), (scheduled_task, 2), (rmm_check_in, 2), (unlock, 1)],
    "server": [(windows_update, 2), (scheduled_task, 2), (rmm_check_in, 2), (server_job, 1)],
}

# Seconds between background activities, per kind of host.
BACKGROUND_GAP: dict[str, tuple[float, float]] = {
    "workstation": (30, 240),
    "jump": (120, 600),
    "server": (180, 900),
}
