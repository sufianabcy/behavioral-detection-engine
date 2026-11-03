"""Put it together: a small company network, a few hours of normal work, and the attacks.

    scenario = generate(ScenarioConfig(seed=7))
    scenario.events      # every event, oldest first, each labelled in meta
    scenario.instances   # the ground truth: which attacks happened, where, when

The same seed always gives the same events, byte for byte, on any computer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from ..event import Event
from . import attacks, benign

from .rand import Rand, derive_seed
from .world import Host, Proc, World

SEEN_CHAINS = ("chain-1", "chain-2", "chain-3", "chain-4")
UNSEEN_CHAINS = ("chain-1u", "chain-2u", "chain-3u")

CHAIN_TITLES: dict[str, str] = {
    "chain-1": "Phishing document: Office starts hidden, encoded PowerShell that calls out, drops a script and persists",
    "chain-2": "Script download: a .js file uses certutil to fetch and decode a DLL, then rundll32 runs it",
    "chain-3": "Lateral movement: remote WMI starts PowerShell on a server, which runs discovery commands",
    "chain-4": "Ransomware preparation: an RDP session deletes backups, clears logs and turns off Defender",
    "chain-1u": "Unseen variant of chain 1: Excel, cmd.exe, short PowerShell flags, scheduled-task persistence",
    "chain-2u": "Unseen variant of chain 2: bitsadmin download and regsvr32 instead of certutil and rundll32",
    "chain-3u": "Unseen variant of chain 3: a remote scheduled task instead of WMI",
}

# (short name, IP, role, primary user). The first `workstations` workstations are used.
WORKSTATIONS = [
    ("WKSTN-07", "10.20.1.37", "jsmith"),
    ("WKSTN-12", "10.20.1.52", "adavis"),  # IT admin: most benign twins happen here
    ("WKSTN-15", "10.20.1.65", "mlopez"),
    ("WKSTN-21", "10.20.1.81", "kchen"),
    ("WKSTN-23", "10.20.1.83", "rpatel"),
    ("WKSTN-31", "10.20.1.91", "tnguyen"),
    ("WKSTN-34", "10.20.1.94", "bokafor"),
    ("WKSTN-38", "10.20.1.98", "lsilva"),
]
ADMIN_WORKSTATION = "WKSTN-12"
JUMP_HOST = ("ADMIN-01", "10.20.0.50", "adm-adavis")
FILE_SERVER = ("SRV-FILE-01", "10.20.0.21")
APP_SERVER = ("SRV-APP-02", "10.20.0.22")
STOLEN_ADMIN = "adm-rpatel"


@dataclass
class ScenarioConfig:
    seed: int = 7
    start: datetime = datetime(2026, 11, 3, 8, 0, tzinfo=timezone.utc)
    hours: float = 3.0
    workstations: int = 5
    chains: tuple[str, ...] = SEEN_CHAINS  # any of SEEN_CHAINS + UNSEEN_CHAINS
    twins: bool = True  # include the benign twins
    background: float = 1.0  # 0 = no background noise, 1 = normal, 2 = twice as busy

    def __post_init__(self) -> None:
        unknown = [c for c in self.chains if c not in CHAIN_TITLES]
        if unknown:
            raise ValueError(f"unknown chain {unknown[0]!r}: choose from {', '.join(CHAIN_TITLES)}")
        if not 3 <= self.workstations <= len(WORKSTATIONS):
            raise ValueError(f"workstations must be between 3 and {len(WORKSTATIONS)}")
        if self.hours < 1:
            raise ValueError("hours must be at least 1")
        if self.background < 0:
            raise ValueError("background can't be negative")


@dataclass
class Instance:
    """One attack that happened: the ground truth for scoring."""

    id: str  # e.g. "chain-1#1"
    chain: str
    variant: str  # "seen" or "unseen"
    hosts: list[str]
    start: datetime
    title: str


@dataclass
class Scenario:
    config: ScenarioConfig
    events: list[Event]
    instances: list[Instance]
    hosts: list[Host] = field(default_factory=list)


def _ms(stamp: datetime) -> datetime:
    """Drop sub-millisecond precision: our JSONL keeps milliseconds, like Sysmon."""
    return stamp.replace(microsecond=stamp.microsecond // 1000 * 1000)


def generate(config: ScenarioConfig | None = None) -> Scenario:
    config = config or ScenarioConfig()
    end = config.start + timedelta(hours=config.hours)
    world = World(Rand(derive_seed(config.seed, "world")), config.start, end)

    workstations = [world.add_host(name, ip, "workstation", user) for name, ip, user in WORKSTATIONS[: config.workstations]]
    admin = world.host(ADMIN_WORKSTATION)
    jump = world.add_host(JUMP_HOST[0], JUMP_HOST[1], "jump", JUMP_HOST[2])
    file_server = world.add_host(*FILE_SERVER, "server")
    app_server = world.add_host(*APP_SERVER, "server")

    if config.background > 0:
        _background(world, config.background, file_server)
    if config.twins:
        _twins(world, Rand(derive_seed(config.seed, "twins")), admin, jump, file_server, app_server, workstations)
    instances = _attacks(world, config, workstations, admin, file_server, app_server)

    # Background activity that started near the end may run past it; drop that tail.
    events = [e for e in world.events if e.timestamp <= end or e.meta.get("label") == "malicious"]
    events.sort(key=lambda e: e.timestamp)  # stable: same-time events keep their order
    # An attack's ground-truth start is its first event, whatever time the plan
    # gave it (chain 4's mstsc, for example, starts before the RDP logon).
    first: dict[str, datetime] = {}
    for event in events:
        first.setdefault(event.meta.get("instance", ""), event.timestamp)
    for instance in instances:
        instance.start = first.get(instance.id, instance.start)
    instances.sort(key=lambda i: i.start)
    return Scenario(config=config, events=events, instances=instances, hosts=world.hosts)


def _background(world: World, busy: float, file_server: Host) -> None:
    for host in world.hosts:
        role = "workstation" if host.role == "workstation" else host.role
        low, high = benign.BACKGROUND_GAP[role]
        t = world.start + world.rand.seconds(0, low)
        while t < world.end:
            activity = world.rand.weighted(benign.BACKGROUND[role])
            activity(world, host, t)
            if role == "workstation" and world.rand.chance(0.15):
                benign.file_share(world, host, t + world.rand.seconds(1, 20), file_server)
            t += world.rand.seconds(low / busy, high / busy)


def _twins(world: World, r: Rand, admin: Host, jump: Host, file_server: Host, app_server: Host,
           workstations: list[Host]) -> None:
    """Schedule every benign twin a fixed number of times, at random moments."""
    span = (world.end - world.start).total_seconds()

    def at() -> datetime:
        return _ms(world.start + timedelta(seconds=r.uniform(0.05, 0.95) * span))

    users = [h for h in workstations if h is not admin]
    # About one of each twin per three hours, so a long soak test sees them often.
    for _ in range(max(1, round(span / 3 / 3600))):
        benign.twin_admin_script(world, admin, at())
        benign.twin_certutil_hash(world, admin, at())
        benign.twin_certutil_crl(world, admin, at())
        benign.twin_admin_discovery(world, admin, at())
        benign.twin_admin_discovery(world, jump, at())
        benign.twin_remote_gpupdate(world, jump, at(), file_server)
        benign.twin_remote_gpupdate(world, jump, at(), app_server)
        benign.twin_backup_admin(world, app_server, at(), jump)
        for host in r.shuffled(users)[:2]:
            benign.twin_rmm_encoded(world, host, at())
        benign.twin_onedrive_run_key(world, r.choice(users), at())
        benign.twin_rundll32_control_panel(world, r.choice(users), at())
        benign.twin_logon_script(world, r.choice(users), at())
    # A rare one: about once per 8 hours somewhere on the servers.
    expected = span / 3600 / 8
    for _ in range(int(expected) + (1 if r.chance(expected - int(expected)) else 0)):
        benign.twin_wmi_management_script(world, r.choice([file_server, app_server]), at())


def _attacks(world: World, config: ScenarioConfig, workstations: list[Host], admin: Host,
             file_server: Host, app_server: Host) -> list[Instance]:
    plan = Rand(derive_seed(config.seed, "plan"))
    span = world.end - world.start
    victims = plan.shuffled([h for h in workstations if h is not admin])
    instances: list[Instance] = []

    def when(low: float, high: float) -> datetime:
        return _ms(world.start + span * plan.uniform(low, high))

    def victim(index: int) -> Host:
        return victims[index % len(victims)]

    def record(chain: str, hosts: list[Host], start: datetime) -> attacks.Label:
        number = sum(1 for i in instances if i.chain == chain) + 1
        instance = Instance(
            id=f"{chain}#{number}", chain=chain, variant="unseen" if chain.endswith("u") else "seen",
            hosts=[h.name for h in hosts], start=start, title=CHAIN_TITLES[chain],
        )
        instances.append(instance)
        return attacks.Label(chain, instance.id, instance.variant)

    def attacker_shell(host: Host, t: datetime, label: attacks.Label) -> Proc:
        """When chain 3 or 4 runs without chain 1, the attacker still needs a foothold."""
        return world.spawn(host.procs["explorer"], "powershell.exe", "powershell.exe -nop -w hidden", t,
                           label("execution", "T1059.001", "T1564.003"))

    chain1_host, implant = victim(0), None
    c2 = attacks.c2_server(Rand(derive_seed(config.seed, "c2")))
    t1 = when(0.08, 0.25)
    if "chain-1" in config.chains:
        label = record("chain-1", [chain1_host], t1)
        implant = attacks.chain1_office_macro(world, Rand(derive_seed(config.seed, "chain-1")), chain1_host, t1,
                                              label, c2=c2)
    if "chain-2" in config.chains:
        t = when(0.1, 0.75)
        label = record("chain-2", [victim(1)], t)
        attacks.chain2_script_certutil(world, Rand(derive_seed(config.seed, "chain-2")), victim(1), t, label)
    t3 = _ms(t1 + span * plan.uniform(0.15, 0.22))
    if "chain-3" in config.chains:
        shell_at = t3 - timedelta(seconds=30)  # the instance starts with the attacker's shell, if we add one
        label = record("chain-3", [chain1_host, file_server], t3 if implant else shell_at)
        launcher = implant or attacker_shell(chain1_host, shell_at, label)
        attacks.chain3_wmi_lateral(world, Rand(derive_seed(config.seed, "chain-3")), chain1_host, file_server, t3,
                                   label, launcher=launcher, account=STOLEN_ADMIN, c2=c2)
    if "chain-4" in config.chains:
        t4 = _ms(t3 + span * plan.uniform(0.12, 0.2))
        shell_at = t4 - timedelta(seconds=40)
        label = record("chain-4", [chain1_host, app_server], t4 if implant else shell_at)
        launcher = implant or attacker_shell(chain1_host, shell_at, label)
        attacks.chain4_ransomware_prep(world, Rand(derive_seed(config.seed, "chain-4")), chain1_host, app_server, t4,
                                       label, account=STOLEN_ADMIN, launcher=launcher)
    if "chain-1u" in config.chains:
        t = when(0.1, 0.8)
        label = record("chain-1u", [victim(2)], t)
        attacks.chain1_office_macro(world, Rand(derive_seed(config.seed, "chain-1u")), victim(2), t, label,
                                    c2=attacks.c2_server(Rand(derive_seed(config.seed, "c2-1u"))), unseen=True)
    if "chain-2u" in config.chains:
        t = when(0.1, 0.8)
        label = record("chain-2u", [victim(3)], t)
        attacks.chain2_script_certutil(world, Rand(derive_seed(config.seed, "chain-2u")), victim(3), t, label,
                                       unseen=True)
    if "chain-3u" in config.chains:
        t = when(0.2, 0.85)
        source = victim(2)
        shell_at = t - timedelta(seconds=45)
        label = record("chain-3u", [source, file_server], shell_at)
        launcher = attacker_shell(source, shell_at, label)
        attacks.chain3u_remote_task(world, Rand(derive_seed(config.seed, "chain-3u")), source, file_server, t, label,
                                    launcher=launcher, account=STOLEN_ADMIN)
    instances.sort(key=lambda i: i.start)
    return instances


