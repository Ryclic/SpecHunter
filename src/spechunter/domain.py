"""Serializable contracts shared by agents, simulators, and CHIA nodes."""

import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from hashlib import sha256


class Op(StrEnum):
    NOP = "nop"
    TRAIN = "train"
    ENTER_USER = "enter_user"
    LOAD_SECRET = "load_secret"
    ENCODE = "encode"
    SQUASH = "squash"
    PROBE = "probe"
    FENCE = "fence"


OP_CODES = {op: i for i, op in enumerate(Op)}


@dataclass(frozen=True)
class Program:
    ops: tuple[Op, ...]

    def __post_init__(self):
        if not self.ops or len(self.ops) > 128 or any(not isinstance(x, Op) for x in self.ops):
            raise ValueError("program must contain 1..128 supported operations")

    @classmethod
    def parse(cls, values: list[str]) -> "Program":
        return cls(tuple(Op(value) for value in values))

    @property
    def digest(self) -> str:
        return sha256(self.to_json().encode()).hexdigest()

    def to_json(self) -> str:
        return json.dumps([op.value for op in self.ops])

    def assembly(self) -> str:
        """Harness calls, NOT a standalone exploit or executable ISA simulation."""
        lines = [
            "# RV64 harness-linked candidate; see docs/BOOM.md.",
            ".section .text",
            ".globl spechunter_candidate",
            "spechunter_candidate:",
            "  addi sp, sp, -16",
            "  sd ra, 8(sp)",
        ]
        for op in self.ops:
            lines.append("  nop" if op == Op.NOP else f"  call spechunter_{op.value}")
        lines += ["  ld ra, 8(sp)", "  addi sp, sp, 16", "  ret", ""]
        return "\n".join(lines)


@dataclass(frozen=True)
class Benchmark:
    id: str
    description: str
    bug: str
    invariant: str
    positive: bool


BENCHMARKS = (
    Benchmark(
        "privilege-bypass",
        "A user load bypasses privilege enforcement",
        "privilege",
        "architectural-isolation",
        True,
    ),
    Benchmark(
        "transient-cache",
        "A denied transient load leaves a secret-dependent cache line",
        "transient",
        "observable-isolation",
        True,
    ),
    Benchmark(
        "secure-control",
        "Privilege checks and speculative cache updates are isolated",
        "none",
        "observable-isolation",
        False,
    ),
)


@dataclass(frozen=True)
class Observation:
    architectural: tuple[int, ...]
    probes: tuple[int, ...]
    events: tuple[str, ...]
    completed: bool = True

    @classmethod
    def from_dict(cls, data: dict) -> "Observation":
        # Malformed, timed-out, or incomplete runs must never become findings.
        if set(data) != {"architectural", "probes", "events", "completed"}:
            raise ValueError("invalid observation fields")
        if data["completed"] is not True:
            raise ValueError("simulator did not complete")
        for key in ("architectural", "probes"):
            if (
                not isinstance(data[key], list)
                or len(data[key]) > 4096
                or any(type(x) is not int for x in data[key])
            ):
                raise ValueError(f"invalid {key}")
        if (
            not isinstance(data["events"], list)
            or len(data["events"]) > 4096
            or any(not isinstance(x, str) or len(x) > 256 for x in data["events"])
        ):
            raise ValueError("invalid events")
        return cls(tuple(data["architectural"]), tuple(data["probes"]), tuple(data["events"]))

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Validation:
    status: str  # violation, clean, inconclusive
    reason: str
    observations: tuple[Observation, ...]

    @property
    def violation(self) -> bool:
        return self.status == "violation"
