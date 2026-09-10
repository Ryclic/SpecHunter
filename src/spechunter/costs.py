"""Persistent conservative cost accounting for paid model calls."""

import json
import os
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path
from uuid import uuid4


@dataclass(frozen=True)
class ModelPricing:
    model: str
    input_per_million_usd: Decimal
    output_per_million_usd: Decimal
    verified_on: date
    source: str

    def __post_init__(self):
        if (
            not self.input_per_million_usd.is_finite()
            or not self.output_per_million_usd.is_finite()
            or self.input_per_million_usd < 0
            or self.output_per_million_usd < 0
        ):
            raise ValueError("model prices must be non-negative")

    def assert_current(self, today: date | None = None, maximum_age_days: int = 30) -> None:
        age = (today or datetime.now(UTC).date()) - self.verified_on
        if age.days < 0 or age.days > maximum_age_days:
            raise ValueError(
                f"pricing for {self.model} is {age.days} days old; verify current official pricing"
            )

    def estimate(self, input_tokens: int, output_tokens: int) -> Decimal:
        if input_tokens < 0 or output_tokens < 0:
            raise ValueError("token counts must be non-negative")
        million = Decimal(1_000_000)
        return (
            Decimal(input_tokens) * self.input_per_million_usd
            + Decimal(output_tokens) * self.output_per_million_usd
        ) / million


VERTEX_PRICING = {
    "gemini-2.5-flash-lite": ModelPricing(
        model="gemini-2.5-flash-lite",
        input_per_million_usd=Decimal("0.10"),
        output_per_million_usd=Decimal("0.40"),
        verified_on=date(2026, 9, 10),
        source="https://cloud.google.com/vertex-ai/generative-ai/pricing",
    )
}


class CostLedger:
    """JSON ledger with an adjacent advisory lock for cross-process reservations."""

    def __init__(self, path: Path, budget_usd: Decimal):
        if not budget_usd.is_finite() or budget_usd <= 0:
            raise ValueError("LLM budget must be positive")
        self.path = path
        self.lock_path = path.with_suffix(path.suffix + ".lock")
        self.budget_usd = budget_usd

    @contextmanager
    def _locked(self):
        import fcntl

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield
            fcntl.flock(lock, fcntl.LOCK_UN)

    def _read(self) -> dict:
        if not self.path.exists():
            return {"schema_version": 1, "entries": []}
        data = json.loads(self.path.read_text())
        if data.get("schema_version") != 1 or not isinstance(data.get("entries"), list):
            raise ValueError("invalid LLM cost ledger")
        return data

    def _write(self, data: dict) -> None:
        handle, name = tempfile.mkstemp(prefix=self.path.name, dir=self.path.parent)
        try:
            with os.fdopen(handle, "w") as output:
                json.dump(data, output, indent=2, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(name, self.path)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    @staticmethod
    def _total(data: dict) -> Decimal:
        return sum((Decimal(entry["amount_usd"]) for entry in data["entries"]), Decimal())

    def reserve(self, amount: Decimal, metadata: dict) -> str:
        if amount <= 0:
            raise ValueError("reservation must be positive")
        with self._locked():
            data = self._read()
            if self._total(data) + amount > self.budget_usd:
                raise RuntimeError(
                    f"LLM budget exhausted: reservation ${amount:.6f} exceeds "
                    f"${self.budget_usd:.2f} run budget"
                )
            reservation = uuid4().hex
            data["entries"].append(
                {
                    "id": reservation,
                    "state": "reserved",
                    "amount_usd": str(amount),
                    "created_at": datetime.now(UTC).isoformat(),
                    **metadata,
                }
            )
            self._write(data)
            return reservation

    def settle(
        self,
        reservation: str,
        amount: Decimal,
        input_tokens: int | None,
        output_tokens: int | None,
        outcome: str,
    ) -> None:
        with self._locked():
            data = self._read()
            entry = next((item for item in data["entries"] if item["id"] == reservation), None)
            if entry is None or entry["state"] != "reserved":
                raise ValueError("unknown or settled cost reservation")
            entry.update(
                state="settled",
                amount_usd=str(amount),
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                outcome=outcome,
                settled_at=datetime.now(UTC).isoformat(),
            )
            self._write(data)

    def summary(self) -> dict:
        with self._locked():
            data = self._read()
            total = self._total(data)
            return {
                "budget_usd": str(self.budget_usd),
                "accounted_usd": str(total),
                "remaining_usd": str(self.budget_usd - total),
                "calls": len(data["entries"]),
                "ledger": str(self.path),
            }
