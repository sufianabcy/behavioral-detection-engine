"""The simulated network: hosts, processes, and the events they produce.

The generator never writes an event by hand. It asks the world to *do*
something ("this process starts that program", "this process connects to
that address") and the world writes the matching Sysmon or Security event,
with the same fields real Sysmon writes. That keeps every event consistent:
a child's ParentProcessGuid always points at a real parent, a network event's
SourceIp is always its host's own address, and so on.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from ..event import SYSMON_CHANNEL, Event, windows_basename
from .catalog import (
    DOMAIN,
    NETBIOS,
    SYSTEM_USER,
    binary,
    fake_hash,
    qualified,
    user_sid,
)
from .rand import Rand

Meta = dict[str, Any]

SECURITY_CHANNEL = "Security"


def _sam(user: str) -> str:
    """'CORP\\jsmith' -> 'jsmith'."""
    return user.rsplit("\\", 1)[-1]


def sysmon_time(stamp: datetime) -> str:
    """Sysmon's UtcTime style: '2026-11-03 09:14:05.093'."""
    return stamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


@dataclass(eq=False)
class Proc:
    """A running process in the simulation."""

    host: Host
    guid: str
    pid: int
    image: str
    command_line: str
    user: str
    integrity: str
    logon_id: str
    session: int
    cwd: str
    parent: Proc | None
    start: datetime

    @property
    def name(self) -> str:
        return windows_basename(self.image)


@dataclass(eq=False)
class Host:
    short: str  # WKSTN-07
    ip: str
    role: str  # workstation | admin-workstation | jump | server
    user: str | None = None  # primary user's sAMAccountName (workstations)
    procs: dict[str, Proc] = field(default_factory=dict)  # named long-running processes
    guid_prefix: str = ""
    _counter: int = 0
    _pids: list[int] = field(default_factory=list)

    @property
    def name(self) -> str:
        return f"{self.short}.{DOMAIN}"

    def __post_init__(self) -> None:
        self.guid_prefix = hashlib.sha256(self.short.encode("utf-8")).hexdigest()[:8]


class World:
    def __init__(self, rand: Rand, start: datetime, end: datetime) -> None:
        self.rand = rand
        self.start = start
        self.end = end
        self.hosts: list[Host] = []
        self.events: list[Event] = []

    # --- hosts and long-running processes ----------------------------------

    def add_host(self, short: str, ip: str, role: str, user: str | None = None) -> Host:
        host = Host(short=short, ip=ip, role=role, user=user)
        self.hosts.append(host)
        self._boot(host)
        return host

    def host(self, short: str) -> Host:
        return next(h for h in self.hosts if h.short == short)

    def _boot(self, host: Host) -> None:
        """Processes that were already running when logging began.

        They never get a process-create event (it happened before the log
        starts), but their children will name them as parents. Phase 1's
        tree turns those into "started before the log began" placeholders.
        """
        boot = self.start - timedelta(hours=self.rand.uniform(20, 70))
        system = self._make(host, "System", "", SYSTEM_USER, None, boot, pid=4)
        smss = self._make(host, "smss.exe", "\\SystemRoot\\System32\\smss.exe", SYSTEM_USER, system, boot)
        services = self._make(host, "services.exe", "C:\\Windows\\system32\\services.exe", SYSTEM_USER, smss, boot)
        winlogon = self._make(host, "winlogon.exe", "winlogon.exe", SYSTEM_USER, smss, boot)
        host.procs.update(system=system, services=services, winlogon=winlogon)

        def svc(name: str, cmd: str, user: str = SYSTEM_USER) -> None:
            host.procs[name] = self._make(host, "svchost.exe", cmd, user, services, boot)

        svc("svc_dcom", "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p")
        svc("svc_netsvcs", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule")
        svc("svc_wu", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s wuauserv")
        svc("svc_bits", "C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s BITS")
        host.procs["wmiprvse"] = self._make(
            host, "WmiPrvSE.exe", "C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding",
            "NT AUTHORITY\\NETWORK SERVICE", host.procs["svc_dcom"], boot + timedelta(minutes=3),
        )
        host.procs["rmm"] = self._make(
            host, "rmm-agent.exe", '"C:\\Program Files\\ExampleRMM\\rmm-agent.exe" --service',
            SYSTEM_USER, services, boot,
        )
        if host.user:  # someone is logged on: their desktop is already open
            logon = self.start - timedelta(minutes=self.rand.uniform(20, 90))
            user = qualified(host.user)
            userinit = self._make(host, "userinit.exe", "C:\\Windows\\system32\\userinit.exe", user, winlogon, logon)
            explorer = self._make(host, "explorer.exe", "C:\\Windows\\Explorer.EXE", user, userinit, logon, session=1)
            host.procs["explorer"] = explorer
            outlook = self._make(
                host, "OUTLOOK.EXE", f'"{binary("OUTLOOK.EXE")[0]}"', user, explorer,
                logon + timedelta(minutes=2), session=1,
            )
            host.procs["outlook"] = outlook

    def _make(
        self,
        host: Host,
        name: str,
        command_line: str,
        user: str,
        parent: Proc | None,
        start: datetime,
        *,
        pid: int | None = None,
        session: int | None = None,
        integrity: str | None = None,
        cwd: str | None = None,
        image: str | None = None,
    ) -> Proc:
        host._counter += 1
        stamp = int(start.timestamp())
        guid = (
            f"{{{host.guid_prefix}-{stamp & 0xFFFF:04x}-{(stamp >> 16) & 0xFFFF:04x}-"
            f"{host._counter:04x}-{self.rand.hex(12)}}}"
        )
        if pid is None:
            pid = self._new_pid(host)
        system_like = user.upper().startswith("NT AUTHORITY")
        if session is None:
            session = parent.session if parent and not system_like else (0 if system_like else 1)
        if integrity is None:
            integrity = "System" if system_like else ("High" if _sam(user).startswith("adm-") else "Medium")
        logon_id = "0x3e7" if user == SYSTEM_USER else ("0x3e4" if system_like else self._logon_id(host, user))
        return Proc(
            host=host,
            guid=guid,
            pid=pid,
            image=image or binary(name)[0],
            command_line=command_line,
            user=user,
            integrity=integrity,
            logon_id=logon_id,
            session=session,
            cwd=cwd or ("C:\\Windows\\system32\\" if system_like else f"C:\\Users\\{_sam(user)}\\"),
            parent=parent,
            start=start,
        )

    def _new_pid(self, host: Host) -> int:
        while True:  # Windows PIDs are multiples of 4
            pid = self.rand.int_between(250, 5000) * 4
            if pid not in host._pids:
                host._pids.append(pid)
                return pid

    def _logon_id(self, host: Host, user: str) -> str:
        digest = hashlib.sha256(f"{host.short}/{user.lower()}".encode("utf-8")).hexdigest()
        return "0x" + digest[:6].lstrip("0")

    # --- actions that write events -----------------------------------------

    def _emit(self, event_id: int, at: datetime, host: Host, data: dict[str, str], meta: Meta,
              channel: str = SYSMON_CHANNEL) -> Event:
        event = Event(event_id=event_id, timestamp=at, host=host.name, channel=channel, data=data, meta=dict(meta))
        self.events.append(event)
        return event

    def spawn(
        self,
        parent: Proc,
        name: str,
        command_line: str,
        at: datetime,
        meta: Meta,
        *,
        user: str | None = None,
        cwd: str | None = None,
        image: str | None = None,
    ) -> Proc:
        """`parent` starts program `name`: a Sysmon event 1 (process create)."""
        host = parent.host
        proc = self._make(host, name, command_line, user or parent.user, parent, at, cwd=cwd, image=image)
        path, original, description = binary(name)
        data = {
            "RuleName": "-",
            "UtcTime": sysmon_time(at),
            "ProcessGuid": proc.guid,
            "ProcessId": str(proc.pid),
            "Image": proc.image,
            "FileVersion": "10.0.22621.1",
            "Description": description,
            "OriginalFileName": original,
            "CommandLine": command_line,
            "CurrentDirectory": proc.cwd,
            "User": proc.user,
            "LogonId": proc.logon_id,
            "TerminalSessionId": str(proc.session),
            "IntegrityLevel": proc.integrity,
            "Hashes": fake_hash(proc.image),
            "ParentProcessGuid": parent.guid,
            "ParentProcessId": str(parent.pid),
            "ParentImage": parent.image,
            "ParentCommandLine": parent.command_line,
            "ParentUser": parent.user,
        }
        self._emit(1, at, host, data, meta)
        return proc

    def connect(
        self,
        proc: Proc,
        at: datetime,
        dest_ip: str,
        dest_port: int,
        meta: Meta,
        *,
        dest_name: str = "",
        protocol: str = "tcp",
    ) -> Event:
        """`proc` opens a connection out: a Sysmon event 3 with Initiated=true."""
        return self._emit(3, at, proc.host, self._net_data(
            proc, at, protocol, True, proc.host.ip, self.rand.int_between(49152, 65000), "",
            dest_ip, dest_port, dest_name,
        ), meta)

    def accept(self, proc: Proc, at: datetime, source_ip: str, local_port: int, meta: Meta) -> Event:
        """`proc` receives a connection: a Sysmon event 3 with Initiated=false."""
        return self._emit(3, at, proc.host, self._net_data(
            proc, at, "tcp", False, source_ip, self.rand.int_between(49152, 65000), "",
            proc.host.ip, local_port, proc.host.name,
        ), meta)

    def _net_data(self, proc: Proc, at: datetime, protocol: str, initiated: bool, src_ip: str, src_port: int,
                  src_name: str, dst_ip: str, dst_port: int, dst_name: str) -> dict[str, str]:
        port_names = {80: "http", 443: "https", 445: "microsoft-ds", 135: "epmap", 5985: "-", 3389: "ms-wbt-server"}
        return {
            "RuleName": "-",
            "UtcTime": sysmon_time(at),
            "ProcessGuid": proc.guid,
            "ProcessId": str(proc.pid),
            "Image": proc.image,
            "User": proc.user,
            "Protocol": protocol,
            "Initiated": "true" if initiated else "false",
            "SourceIsIpv6": "false",
            "SourceIp": src_ip,
            "SourceHostname": src_name or (proc.host.name if initiated else "-"),
            "SourcePort": str(src_port),
            "SourcePortName": "-",
            "DestinationIsIpv6": "false",
            "DestinationIp": dst_ip,
            "DestinationHostname": dst_name or "-",
            "DestinationPort": str(dst_port),
            "DestinationPortName": port_names.get(dst_port, "-"),
        }

    def dns(self, proc: Proc, at: datetime, query: str, answer_ip: str, meta: Meta) -> Event:
        """`proc` looks up a name: a Sysmon event 22."""
        return self._emit(22, at, proc.host, {
            "RuleName": "-",
            "UtcTime": sysmon_time(at),
            "ProcessGuid": proc.guid,
            "ProcessId": str(proc.pid),
            "QueryName": query,
            "QueryStatus": "0",
            "QueryResults": f"::ffff:{answer_ip};",
            "Image": proc.image,
            "User": proc.user,
        }, meta)

    def lookup_and_connect(self, proc: Proc, at: datetime, site: tuple[str, str], port: int, meta: Meta) -> datetime:
        """DNS lookup, then the connection a moment later. Returns the time after both."""
        name, ip = site
        self.dns(proc, at, name, ip, meta)
        at += self.rand.seconds(0.02, 0.25)
        self.connect(proc, at, ip, port, meta, dest_name=name)
        return at

    def create_file(self, proc: Proc, at: datetime, path: str, meta: Meta) -> Event:
        """`proc` writes a new file: a Sysmon event 11."""
        return self._emit(11, at, proc.host, {
            "RuleName": "-",
            "UtcTime": sysmon_time(at),
            "ProcessGuid": proc.guid,
            "ProcessId": str(proc.pid),
            "Image": proc.image,
            "TargetFilename": path,
            "CreationUtcTime": sysmon_time(at),
            "User": proc.user,
        }, meta)

    def set_registry(self, proc: Proc, at: datetime, key: str, value: str, meta: Meta) -> Event:
        """`proc` sets a registry value: a Sysmon event 13."""
        return self._emit(13, at, proc.host, {
            "RuleName": "-",
            "EventType": "SetValue",
            "UtcTime": sysmon_time(at),
            "ProcessGuid": proc.guid,
            "ProcessId": str(proc.pid),
            "Image": proc.image,
            "TargetObject": key,
            "Details": value,
            "User": proc.user,
        }, meta)

    def run_key(self, user_sam: str, name: str) -> str:
        """The per-user Run key as Sysmon writes it (HKU\\<SID>\\...)."""
        return f"HKU\\{user_sid(user_sam)}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{name}"

    def logon(
        self,
        host: Host,
        at: datetime,
        user_sam: str,
        logon_type: int,
        meta: Meta,
        *,
        source_ip: str = "-",
        workstation: str = "-",
        package: str = "Kerberos",
    ) -> Event:
        """Someone logs on to `host`: Security event 4624."""
        process = {2: ("User32 ", "C:\\Windows\\System32\\svchost.exe"),
                   7: ("User32 ", "C:\\Windows\\System32\\svchost.exe"),
                   10: ("User32 ", "C:\\Windows\\System32\\svchost.exe")}.get(logon_type, ("Kerberos", "-"))
        return self._emit(4624, at, host, {
            "SubjectUserSid": "S-1-5-18" if logon_type != 3 else "S-1-0-0",
            "SubjectUserName": f"{host.short}$" if logon_type != 3 else "-",
            "SubjectDomainName": NETBIOS if logon_type != 3 else "-",
            "SubjectLogonId": "0x3e7" if logon_type != 3 else "0x0",
            "TargetUserSid": user_sid(user_sam),
            "TargetUserName": user_sam,
            "TargetDomainName": NETBIOS,
            "TargetLogonId": "0x" + self.rand.hex(7).lstrip("0"),
            "LogonType": str(logon_type),
            "LogonProcessName": process[0] if logon_type != 3 else ("NtLmSsp " if package == "NTLM" else "Kerberos"),
            "AuthenticationPackageName": "Negotiate" if logon_type != 3 else package,
            "WorkstationName": workstation,
            "LogonGuid": "{" + self.rand.hex(8) + "-" + self.rand.hex(4) + "-" + self.rand.hex(4) + "-"
            + self.rand.hex(4) + "-" + self.rand.hex(12) + "}",
            "ProcessName": process[1] if logon_type != 3 else "-",
            "IpAddress": source_ip,
            "IpPort": str(self.rand.int_between(49152, 65000)) if source_ip != "-" else "-",
            "ImpersonationLevel": "%%1833",
            "ElevatedToken": "%%1842" if user_sam.startswith("adm-") else "%%1843",
        }, meta, channel=SECURITY_CHANNEL)

    def log_cleared(self, host: Host, at: datetime, user_sam: str, meta: Meta) -> Event:
        """The Security log was cleared: Security event 1102 (written by the log itself)."""
        return self._emit(1102, at, host, {
            "SubjectUserSid": user_sid(user_sam),
            "SubjectUserName": user_sam,
            "SubjectDomainName": NETBIOS,
            "SubjectLogonId": "0x" + self.rand.hex(6).lstrip("0"),
        }, meta, channel=SECURITY_CHANNEL)
