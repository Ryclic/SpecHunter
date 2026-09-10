import json
from datetime import date
from decimal import Decimal

import pytest

from spechunter.costs import CostLedger, ModelPricing


def test_pricing_estimate_and_freshness():
    pricing = ModelPricing(
        "test", Decimal("1.00"), Decimal("2.00"), date(2026, 9, 1), "https://example.test"
    )
    assert pricing.estimate(1_000_000, 500_000) == Decimal("2.00")
    pricing.assert_current(date(2026, 9, 30))
    with pytest.raises(ValueError, match="verify current official pricing"):
        pricing.assert_current(date(2026, 10, 2))


def test_ledger_reserves_settles_and_persists(tmp_path):
    path = tmp_path / "cost.json"
    ledger = CostLedger(path, Decimal("1.00"))
    reservation = ledger.reserve(Decimal("0.25"), {"model": "test"})
    assert ledger.summary()["accounted_usd"] == "0.25"

    ledger.settle(reservation, Decimal("0.10"), 10, 20, "success")
    assert CostLedger(path, Decimal("1.00")).summary() == {
        "budget_usd": "1.00",
        "accounted_usd": "0.10",
        "remaining_usd": "0.90",
        "calls": 1,
        "ledger": str(path),
    }
    entry = json.loads(path.read_text())["entries"][0]
    assert entry["state"] == "settled"
    assert entry["input_tokens"] == 10
    assert entry["output_tokens"] == 20


def test_ledger_rejects_over_budget(tmp_path):
    ledger = CostLedger(tmp_path / "cost.json", Decimal("0.10"))
    ledger.reserve(Decimal("0.08"), {})
    with pytest.raises(RuntimeError, match="budget exhausted"):
        ledger.reserve(Decimal("0.03"), {})
