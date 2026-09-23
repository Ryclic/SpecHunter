"""Example demonstrating SpecHunter as a composable CHIA security block
across multiple benchmarks."""

from spechunter.backends import BackendConfig
from spechunter.chia_nodes import SpecHunterSecurityAuditBlock


def audit_target(name: str, benchmark_id: str):
    print(f"\n--- Auditing Target: {name} ({benchmark_id}) ---")
    audit_block = SpecHunterSecurityAuditBlock(
        config=BackendConfig(),
        strategy="guided",
        iterations=4,
        seed=42,
        benchmark_id=benchmark_id,
    )
    report = audit_block.execute(local=True)
    orchestration = report.get("orchestration", {})
    metrics = report.get("metrics", {})

    print(f"  CHIA Engine:       {orchestration.get('engine', 'local')}")
    print(f"  Vulnerabilities:   {metrics.get('discovered', 0)}")
    print(f"  False Positives:   {metrics.get('false_positives', 0)}")
    print(f"  Sim Executions:    {metrics.get('executions', 0)}")
    verdict = "CLEAN" if metrics.get("discovered", 0) == 0 else "VIOLATION_CONFIRMED"
    print(f"  Verdict:           {verdict}")
    return report


def main():
    print("=== SpecHunter Multi-Benchmark CHIA Co-Design Security Pipeline ===")
    targets = [
        ("Spectre-v1 (Transient Cache)", "transient-cache"),
        ("Meltdown (Privilege Bypass)", "privilege-bypass"),
        ("Secure Baseline (Control)", "secure-control"),
    ]
    for label, bid in targets:
        audit_target(label, bid)
    print("\n✓ Full CHIA security pipeline audit completed successfully!")


if __name__ == "__main__":
    main()
