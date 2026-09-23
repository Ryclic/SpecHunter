"""Example demonstrating SpecHunter as a composable CHIA security block."""

from spechunter.backends import BackendConfig
from spechunter.chia_nodes import SpecHunterSecurityAuditBlock


def main():
    print("=== SpecHunter CHIA Composable Block Execution ===")

    # Initialize the SpecHunter block with configured targets
    audit_block = SpecHunterSecurityAuditBlock(
        config=BackendConfig(),
        strategy="guided",
        iterations=4,
        seed=42,
    )

    print("Executing SpecHunter block on local Ray runtime...")
    report = audit_block.execute(local=True)

    orchestration = report.get("orchestration", {})
    metrics = report.get("metrics", {})

    print(f"CHIA Engine:       {orchestration.get('engine')}")
    print(f"CHIA Version:      {orchestration.get('chialoops_version')}")
    print(f"Ray Version:       {orchestration.get('ray_version')}")
    print(f"Vulnerabilities:   {metrics.get('discovered')}")
    print(f"False Positives:   {metrics.get('false_positives')}")
    print(f"Sim Executions:    {metrics.get('executions')}")
    print("\nSpecHunter block successfully audited target!")


if __name__ == "__main__":
    main()
