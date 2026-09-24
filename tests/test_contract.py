"""Tests for Speculation Contracts & Dual-Rail Formal Miter Equivalence Prover."""

import json
from pathlib import Path

from spechunter.contract import ContractType, SpeculationContractEngine


def test_contract_variants():
    engine = SpeculationContractEngine(depth=8)
    repaired_c = engine.get_contract_for_variant("repaired")
    strict_c = engine.get_contract_for_variant("strict")
    uncheck_c = engine.get_contract_for_variant("baseline")

    assert repaired_c.contract_type == ContractType.SANDBOXED_TRANSIENT
    assert repaired_c.sandbox_enforced
    assert repaired_c.privilege_gated

    assert strict_c.contract_type == ContractType.STRICT_INORDER
    assert strict_c.max_speculation_depth == 0

    assert uncheck_c.contract_type == ContractType.UNCHECKED_SPECULATION
    assert not uncheck_c.sandbox_enforced
    assert len(uncheck_c.allowed_leakage_elements) > 2


def test_miter_verification():
    engine = SpeculationContractEngine(depth=8)
    result = engine.verify_miter("transient-cache")

    assert result.benchmark_id == "transient-cache"
    assert result.functional_equivalence_proven
    assert result.security_isolation_proven
    assert result.speculative_leak_baseline
    assert not result.speculative_leak_repaired
    assert not result.architectural_mismatch_detected
    assert result.verdict == "FORMAL_MITER_EQUIVALENCE_AND_ISOLATION_PROVEN"


def test_miter_smt2_and_chisel_generation():
    engine = SpeculationContractEngine(depth=6)
    contract = engine.get_contract_for_variant("repaired")
    smt2_code, clauses = engine.generate_smt2_miter("privilege-bypass", contract)

    assert "(set-logic QF_BV)" in smt2_code
    assert "baseline_arch_pc" in smt2_code
    assert "repaired_arch_pc" in smt2_code
    assert "(check-sat)" in smt2_code
    assert clauses > 10

    chisel_code = engine.generate_chisel_miter("privilege-bypass")
    assert "class DualRailMiterComparator" in chisel_code
    assert "class DualRailMiterVerificationSpec" in chisel_code
    assert "dut.io.arch_equivalent.expect(true.B)" in chisel_code


def test_contract_serialization(tmp_path: Path):
    engine = SpeculationContractEngine(depth=8)
    result = engine.verify_miter("issue-715")

    json_str = result.to_json()
    data = json.loads(json_str)
    assert data["benchmark_id"] == "issue-715"
    assert data["functional_equivalence_proven"]

    md_str = result.to_markdown()
    assert "# SpecHunter Formal Dual-Rail Miter Verification: issue-715" in md_str
    assert "Functional Preservation Hyperproperty" in md_str

    out_file = tmp_path / "miter_proof.smt2"
    engine.export_miter(out_file, result)
    assert out_file.exists()
    assert "(set-logic QF_BV)" in out_file.read_text(encoding="utf-8")
