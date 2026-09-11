"""Offline semantic fixture, executable RTL fixture, and external BOOM trace boundary."""

import json
import shutil
import tempfile
from dataclasses import dataclass
from hashlib import sha256
from importlib.resources import files
from pathlib import Path

from spechunter.domain import OP_CODES, Observation, Op, Program
from spechunter.process import ExecutionError, run


@dataclass(frozen=True)
class BackendConfig:
    kind: str = "model"
    command: tuple[str, ...] = ()
    timeout_seconds: int = 30
    target_revision: str = ""

    def __post_init__(self):
        if self.kind not in {"model", "rtl", "boom"}:
            raise ValueError("unknown backend")
        if not 1 <= self.timeout_seconds <= 3600:
            raise ValueError("timeout must be 1..3600 seconds")
        if self.kind == "boom" and (not self.command or not self.target_revision):
            raise ValueError("BOOM requires a trusted runner command and target revision")


def model(program: Program, secret: int, bug: str) -> Observation:
    """Toy state machine; this does not simulate a RISC-V core."""
    user = trained = speculative = valid = False
    value = 0
    cache: set[int] = set()
    architectural, probes, events = [], [], []
    for op in program.ops:
        if op == Op.TRAIN:
            trained = True
        elif op == Op.ENTER_USER:
            user = True
        elif op == Op.LOAD_SECRET:
            speculative = trained
            valid = not user or bug == "privilege" or (bug == "transient" and speculative)
            if valid:
                value = secret
            if user:
                events.append("transient-load" if speculative else "user-load")
                if valid and not speculative:
                    architectural.append(value)
        elif op == Op.ENCODE and valid:
            if not speculative or bug == "transient":
                cache.add(value)
        elif op == Op.SQUASH:
            speculative = valid = trained = False
        elif op == Op.PROBE and user:
            # Observer always probes the SAME public line in both secret worlds.
            probes.append(1 if 0 in cache else 10)
        elif op == Op.FENCE:
            trained = speculative = valid = False
    return Observation(tuple(architectural), tuple(probes), tuple(events))


class Backend:
    def __init__(self, config: BackendConfig):
        self.config = config
        self.executions = 0
        self._temp = tempfile.TemporaryDirectory(prefix="spechunter-backend-")
        self.directory = Path(self._temp.name)
        self.binary: Path | None = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._temp.cleanup()

    def execute(self, program: Program, secret: int, bug: str) -> Observation:
        if secret not in (0, 1) or bug not in {
            "none",
            "privilege",
            "transient",
            "gate-faulting-loads",
        }:
            raise ValueError("invalid fixture parameters")
        self.executions += 1
        if self.config.kind == "model":
            return model(program, secret, bug)
        if self.config.kind == "rtl":
            return self._rtl(program, secret, bug)
        return self._boom(program, secret, bug)

    def _rtl(self, program: Program, secret: int, bug: str) -> Observation:
        if self.binary is None:
            if not shutil.which("iverilog") or not shutil.which("vvp"):
                raise ExecutionError("RTL backend needs iverilog and vvp; see docs/DEVELOPMENT.md")
            source = self.directory / "fixture.sv"
            source.write_text(files("spechunter.rtl").joinpath("fixture.sv").read_text())
            self.binary = self.directory / "fixture.vvp"
            run(
                ["iverilog", "-g2012", "-s", "fixture", "-o", str(self.binary), str(source)],
                self.directory,
                self.config.timeout_seconds,
            )
        program_file = self.directory / "program.hex"
        program_file.write_text("\n".join(f"{OP_CODES[x]:02x}" for x in program.ops) + "\n")
        bug_code = {"none": 0, "privilege": 1, "transient": 2}[bug]
        output = run(
            [
                "vvp",
                str(self.binary),
                f"+PROGRAM={program_file}",
                f"+LENGTH={len(program.ops)}",
                f"+SECRET={secret}",
                f"+BUG={bug_code}",
            ],
            self.directory,
            self.config.timeout_seconds,
        )
        arch, probes, events = [], [], []
        done = False
        for line in output.splitlines():
            if line.startswith("ARCH "):
                arch.append(int(line[5:]))
            elif line.startswith("PROBE "):
                probes.append(int(line[6:]))
            elif line.startswith("EVENT "):
                events.append(line[6:])
            elif line == "DONE":
                done = True
            else:
                raise ExecutionError(f"unexpected RTL output: {line[:200]}")
        if not done:
            raise ExecutionError("RTL simulation did not complete")
        return Observation(tuple(arch), tuple(probes), tuple(events))

    def _boom(self, program: Program, secret: int, bug: str) -> Observation:
        # A trusted integration runner supplies privilege setup, compiler, simulator,
        # and trace instrumentation. Arbitrary LLM-produced commands are never executed.
        with tempfile.TemporaryDirectory(dir=self.directory) as directory:
            work = Path(directory)
            request = {
                "schema_version": 1,
                "program": [x.value for x in program.ops],
                "program_sha256": program.digest,
                "secret": secret,
                "variant": bug,
                "target_revision": self.config.target_revision,
            }
            (work / "request.json").write_text(json.dumps(request))
            (work / "candidate.S").write_text(program.assembly())
            output = run(
                [*self.config.command, str(work / "request.json")],
                work,
                self.config.timeout_seconds,
            )
            try:
                data = json.loads(output)
                if (
                    data["schema_version"] != 1
                    or data["target"] != "boom"
                    or data["target_revision"] != self.config.target_revision
                    or data["program_sha256"] != program.digest
                    or data["secret"] != secret
                    or data["variant"] != bug
                ):
                    raise ValueError("trace provenance mismatch")
                return Observation.from_dict(data["observation"])
            except (ValueError, KeyError, TypeError) as exc:
                raise ExecutionError(f"invalid BOOM trace: {exc}") from exc

    def provenance(self) -> dict:
        return {
            "kind": self.config.kind,
            "target_revision": self.config.target_revision or "spechunter-fixture-v1",
            "fixture_sha256": sha256(
                files("spechunter.rtl").joinpath("fixture.sv").read_bytes()
            ).hexdigest()
            if self.config.kind == "rtl"
            else None,
            "command": list(self.config.command),
            "is_boom_evidence": self.config.kind == "boom",
        }
