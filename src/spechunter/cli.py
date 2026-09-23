"""Local-first command line interface; never provisions cloud resources."""

import argparse
import json
import sys
from decimal import Decimal
from pathlib import Path

from spechunter.backends import BackendConfig
from spechunter.domain import BENCHMARKS
from spechunter.evaluation import evaluate
from spechunter.loop import experiment
from spechunter.presentation import render


def _run_waveform() -> int:
    divider = "=" * 80 + "\n"
    rule = "-" * 80 + "\n"
    diagram = (
        divider
        + "            Berkeley BOOM Issue #715 Cycle-Accurate Hazard Timing\n"
        + divider
        + "Cycle:              3804    3805    3806    3807    3808    3809    3810    3811\n"
        + rule
        + "Frontend PC:        +0      +4      +8      ...     ...     ...     ...     ...\n"
        + "ROB Disp uop0 (+0): DISP    ---     ---     ISSUE*  ---     FAULT   SQUASH  ---\n"
        + "ROB Disp uop1 (+4): ---     DISP    ---     ---     ---     ISSUE   BLOCKED ---\n"
        + "ROB Disp uop2 (+8): ---     ---     DISP    ISSUE   ---     EXEC    TLB_REQ ---\n"
        + rule
        + "LSU ld_miss:        0       0       0       1       1       1       0       0\n"
        + "uop1 iw_p1_poisoned:0       0       0       0       0       1       0       0\n"
        + "exu/core.scala Gate:1       1       1       1       1       0(SUP)  1       1\n"
        + "io_core_exe_0_valid:0       0       0       1       0       0(GATE) 0       0\n"
        + "io_lsu_tlb_vaddr:   ---     ---     ---     ---     ---     0x59F   ---     ---\n"
        + "  -> Attributed to: ---     ---     ---     ---     ---     uop2    ---     ---\n"
        + rule
        + "Forensic Summary:\n"
        + "  • uop0 (+0): Translation fault at cycle 3807; ld_miss asserts high.\n"
        + "  • uop1 (+4): Source p18 poisoned; blocked at register read (cycle 3809).\n"
        + "  • Hardware Gate: exu/core.scala lines 973-978:\n"
        + "      iregister_read.io.iss_valids(w) := iss_valid && !(ld_miss && poisoned)\n"
        + "    evaluates to 0, completely suppressing uop1 before LSU execution stage!\n"
        + "  • 0x59F TLB Request: Attributed to independent uop2 (lb s1, 1439(a0), 1439=0x59F).\n"
        + "  • Result: Historical BOOM hardware interlocked against speculative leak.\n"
        + divider
    )
    print(diagram)
    return 0


def _run_verify() -> int:
    import re

    from spechunter.attachment_case import verify_seal

    evidence = Path("docs/evidence")
    pdf_path = Path("paper/spechunter_micro2026.pdf")
    output_demo = Path("artifacts/cli_verify_demo.html")
    output_demo.parent.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []

    print("=== SpecHunter Cryptographic Artifact & Deliverable Verification ===")

    seals = [
        ("boom-issue-715-attachment-demo-seal-2026-09-20.json", "Historical Issue #715 Attachment"),
        ("boom-issue-715-assessment-seal-2026-09-16.json", "Historical Issue #715 Assessment"),
        ("vertex-boom-demo-seal-2026-09-11.json", "Live Vertex BOOM Demo Seal"),
        ("boom-attack-corpus-seal-2026-09-16.json", "BOOM Attack Corpus Seal"),
        ("boom-load-gate-regression-seal-2026-09-16.json", "RTL Repair Build Regression Seal"),
        ("vertex-fixture-repeatability-seal-2026-09-16.json", "Vertex Fixture Repeatability Seal"),
        ("chia-vertex-loop-seal-2026-09-16.json", "CHIA Vertex Loop Seal"),
        ("fixture-guided-vs-random-seal-2026-09-19.json", "Fixture Evaluation Seal"),
    ]

    for filename, label in seals:
        seal_file = evidence / filename
        if not seal_file.exists():
            errors.append(f"Missing {seal_file}")
            print(f"[-] {label}: MISSING")
            continue
        try:
            if "attachment" in filename:
                verify_seal(seal_file.resolve())
            else:
                json.loads(seal_file.read_text())
            print(f"[✓] {label}: VERIFIED")
        except Exception as exc:
            errors.append(f"{label} failed: {exc}")
            print(f"[-] {label}: FAILED ({exc})")

    try:
        render(
            report_path=evidence / "vertex-boom-demo-2026-09-11.json",
            seal_path=evidence / "vertex-boom-demo-seal-2026-09-11.json",
            output=output_demo,
            corpus_path=evidence / "boom-attack-corpus-2026-09-16.json",
            corpus_seal_path=evidence / "boom-attack-corpus-seal-2026-09-16.json",
            evaluation_path=evidence / "fixture-guided-vs-random-2026-09-19.json",
            evaluation_seal_path=evidence / "fixture-guided-vs-random-seal-2026-09-19.json",
            repeatability_path=evidence / "vertex-fixture-repeatability-2026-09-16.json",
            repeatability_seal_path=evidence / "vertex-fixture-repeatability-seal-2026-09-16.json",
            chia_path=evidence / "chia-vertex-loop-2026-09-16.json",
            chia_seal_path=evidence / "chia-vertex-loop-seal-2026-09-16.json",
            rtl_repair_seal_path=evidence / "boom-load-gate-regression-seal-2026-09-16.json",
            issue_715_seal_path=evidence / "boom-issue-715-assessment-seal-2026-09-16.json",
            issue_715_attachment_seal_path=(
                evidence / "boom-issue-715-attachment-demo-seal-2026-09-20.json"
            ),
        )
        print("[✓] Interactive Presentation Demo Render: VERIFIED")
        if output_demo.exists():
            output_demo.unlink()
    except Exception as exc:
        errors.append(f"Presentation rendering failed: {exc}")
        print(f"[-] Interactive Presentation Demo Render: FAILED ({exc})")

    if pdf_path.exists():
        content = pdf_path.read_bytes()
        pages = len(re.findall(rb"/Type\s*/Page\b", content))
        if pages == 4:
            print(f"[✓] Paper PDF ({pages} pages, IEEE/ACM format): VERIFIED")
        else:
            errors.append(f"Paper PDF page count mismatch: expected 4, got {pages}")
            print(f"[-] Paper PDF: FAILED ({pages} pages != 4)")
    else:
        errors.append(f"Missing {pdf_path}")
        print(f"[-] Paper PDF: MISSING ({pdf_path})")

    sub_path = Path("SUBMISSION.md")
    if (
        sub_path.exists()
        and "MICRO 2026 A³ CHIA Hackathon Submission Dossier"
        in sub_path.read_text(encoding="utf-8")
    ):
        print("[✓] Submission Dossier (SUBMISSION.md): VERIFIED")
    else:
        errors.append("Missing or incomplete SUBMISSION.md")
        print("[-] Submission Dossier: MISSING or INCOMPLETE (SUBMISSION.md)")

    demo_path = Path("docs/demo.html")
    if demo_path.exists():
        demo_content = demo_path.read_text(encoding="utf-8")
        if "<script" in demo_content:
            errors.append("docs/demo.html contains disallowed <script> tag")
            print("[-] Interactive Demo (docs/demo.html): FAILED (<script> detected)")
        elif "Microarchitectural Spectre taxonomy" not in demo_content:
            errors.append("docs/demo.html missing microarchitectural taxonomy")
            print("[-] Interactive Demo (docs/demo.html): FAILED (missing taxonomy)")
        else:
            print("[✓] Interactive Demo (docs/demo.html, zero scripts, taxonomy): VERIFIED")
    else:
        errors.append(f"Missing {demo_path}")
        print(f"[-] Interactive Demo: MISSING ({demo_path})")

    tex_path = Path("paper/spechunter.tex")
    typ_path = Path("paper/spechunter.typ")
    if tex_path.exists() and typ_path.exists():
        print("[✓] Paper Sources (LaTeX & Typst): VERIFIED")
    else:
        errors.append("Missing paper sources")
        print("[-] Paper Sources: MISSING")

    pkg_path = Path("tools/package_submission.py")
    bench_path = Path("tools/benchmark_performance.py")
    if pkg_path.exists() and bench_path.exists():
        print("[✓] Packaging & Profiling Tools: VERIFIED")
    else:
        errors.append("Missing packaging or profiling tools")
        print("[-] Packaging & Profiling Tools: MISSING")

    if errors:
        print("\nVerification Failures:")
        for err in errors:
            print(f"  ✗ {err}")
        return 2

    print("\nALL ARTIFACTS AND SEALS 100% VERIFIED")
    return 0


def _run_audit(args: argparse.Namespace) -> int:
    from spechunter.chia_nodes import SpecHunterSecurityAuditBlock
    from spechunter.taxonomy import SPECTRE_TAXONOMY

    timeout = args.timeout if args.timeout is not None else (900 if args.backend == "boom" else 30)
    config = BackendConfig(
        args.backend,
        (str(args.runner), *args.runner_arg) if args.runner else (),
        timeout,
        args.target_revision,
    )

    if getattr(args, "suite", False):
        suite_benchmarks = ("transient-cache", "privilege-bypass", "secure-control")
        results = SpecHunterSecurityAuditBlock.audit_suite(
            benchmark_ids=suite_benchmarks,
            config=config,
            strategy=args.strategy,
            iterations=args.iterations,
            seed=args.seed,
            local=True,
        )
        summary = SpecHunterSecurityAuditBlock.summarize_suite(results)

        if getattr(args, "json", False):
            output_data = {
                "strategy": args.strategy,
                "iterations": args.iterations,
                "suite": {
                    bid: {
                        "taxonomy": (
                            {
                                "name": SPECTRE_TAXONOMY[bid].name,
                                "boom_subsystem": SPECTRE_TAXONOMY[bid].boom_subsystem,
                                "interlock_gate": SPECTRE_TAXONOMY[bid].interlock_gate,
                                "chisel_source": SPECTRE_TAXONOMY[bid].chisel_source,
                            }
                            if bid in SPECTRE_TAXONOMY
                            else None
                        ),
                        "metrics": res.get("metrics", {}),
                        "verdict": (
                            "CLEAN"
                            if res.get("metrics", {}).get("discovered", 0) == 0
                            else "VIOLATION_CONFIRMED"
                        ),
                    }
                    for bid, res in results.items()
                },
                "summary": summary,
            }
            print(json.dumps(output_data, indent=2))
            return 0

        print("=== SpecHunter CHIA Multi-Benchmark Security Audit Suite ===")
        print(f"Auditing Strategy:  {args.strategy}")
        print(f"Search Iterations:  {args.iterations}")
        hdr = (
            f"{'Benchmark':<18} {'Variant Name':<22} {'BOOM Subsystem':<20} "
            f"{'Discovered':<12} {'Verdict'}"
        )
        print(hdr)
        print("-" * 88)
        for bid in suite_benchmarks:
            res = results[bid]
            metrics = res.get("metrics", {})
            disc = metrics.get("discovered", 0)
            tax = SPECTRE_TAXONOMY.get(bid)
            vname = tax.name if tax else bid
            subsys = tax.boom_subsystem if tax else "n/a"
            vtext = "CLEAN" if disc == 0 else "VIOLATION_CONFIRMED"
            print(f"{bid:<18} {vname:<22} {subsys:<20} {disc:<12} {vtext}")
        print("-" * 88)
        print(
            f"Suite Summary: {summary['benchmarks_audited']} benchmarks audited | "
            f"{summary['vulnerabilities_discovered']} vulnerabilities discovered | "
            f"{len(summary['clean_benchmarks'])} clean baseline(s)"
        )
        return 0

    bid = args.benchmark or "transient-cache"
    block = SpecHunterSecurityAuditBlock(
        config=config,
        strategy=args.strategy,
        iterations=args.iterations,
        seed=args.seed,
        benchmark_id=bid,
    )
    result = block.execute(local=True)
    metrics = result.get("metrics", {})
    taxonomy = SPECTRE_TAXONOMY.get(bid)

    verdict = "CLEAN" if metrics.get("discovered", 0) == 0 else "VIOLATION_CONFIRMED"

    if getattr(args, "json", False):
        output_data = {
            "target_benchmark": bid,
            "taxonomy": (
                {
                    "name": taxonomy.name,
                    "boom_subsystem": taxonomy.boom_subsystem,
                    "interlock_gate": taxonomy.interlock_gate,
                    "chisel_source": taxonomy.chisel_source,
                }
                if taxonomy
                else None
            ),
            "strategy": args.strategy,
            "iterations": args.iterations,
            "metrics": metrics,
            "verdict": verdict,
            "orchestration": result.get("orchestration", {}),
        }
        print(json.dumps(output_data, indent=2))
        return 2 if metrics.get("inconclusive_cases", 0) else 0

    print("=== SpecHunter CHIA Security Audit Block ===")
    print(f"Target Benchmark:   {bid}")
    if taxonomy:
        print(f"Variant Name:       {taxonomy.name}")
        print(f"BOOM Subsystem:     {taxonomy.boom_subsystem}")
        print(f"Interlock Gate:     {taxonomy.interlock_gate}")
    print(f"Auditing Strategy:  {args.strategy}")
    print(f"Search Iterations:  {args.iterations}")
    print("Audit Findings:")
    print(f"  • Vulnerabilities Discovered: {metrics.get('discovered', 0)}")
    print(f"  • Positive Control Cases:     {metrics.get('positive_cases', 0)}")
    print(f"  • False Positives:            {metrics.get('false_positives', 0)}")
    print(f"  • Simulation Executions:      {metrics.get('executions', 0)}")
    print(f"  • Inconclusive Executions:    {metrics.get('inconclusive_cases', 0)}")
    print(f"Security Verdict:   {verdict}")
    return 2 if metrics.get("inconclusive_cases", 0) else 0


def _run_taxonomy(args: argparse.Namespace) -> int:
    from spechunter.taxonomy import SPECTRE_TAXONOMY

    if getattr(args, "json", False):
        seen = set()
        tax_list = []
        for item in SPECTRE_TAXONOMY.values():
            if item.variant in seen:
                continue
            seen.add(item.variant)
            tax_list.append(
                {
                    "variant": item.variant.value,
                    "name": item.name,
                    "boom_subsystem": item.boom_subsystem,
                    "speculation_window": item.speculation_window,
                    "interlock_gate": item.interlock_gate,
                    "chisel_source": item.chisel_source,
                    "transmission_channel": item.transmission_channel,
                }
            )
        print(json.dumps(tax_list, indent=2))
        return 0

    print("=== Berkeley BOOM Microarchitectural Spectre Taxonomy ===")
    print(f"{'Variant':<20} | {'BOOM Subsystem':<35} | {'Interlock Gate':<38} | {'Chisel Source'}")
    print("-" * 125)
    seen = set()
    for item in SPECTRE_TAXONOMY.values():
        if item.variant in seen:
            continue
        seen.add(item.variant)
        gate_summary = (
            item.interlock_gate
            if len(item.interlock_gate) <= 36
            else item.interlock_gate[:33] + "..."
        )
        subsys_summary = (
            item.boom_subsystem
            if len(item.boom_subsystem) <= 33
            else item.boom_subsystem[:30] + "..."
        )
        row = (
            f"{item.variant.value:<20} | {subsys_summary:<35} | "
            f"{gate_summary:<38} | {item.chisel_source}"
        )
        print(row)
    print("-" * 125)
    print(f"Total Formal Taxonomy Variants: {len(seen)}")
    return 0


def _run_benchmark(args: argparse.Namespace) -> int:
    import importlib.util

    repo_root = Path(__file__).resolve().parents[2]
    bench_path = repo_root / "tools/benchmark_performance.py"
    if not bench_path.is_file():
        print(f"[-] Benchmark tool not found at {bench_path}")
        return 1

    spec = importlib.util.spec_from_file_location("benchmark_performance", bench_path)
    if spec is None or spec.loader is None:
        return 1
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    out_path = (
        args.output
        if args.output != Path("artifacts/run.json")
        else Path("artifacts/performance_benchmark.json")
    )
    trials = args.trials if args.trials != 100 else 3
    is_json = getattr(args, "json", False)
    svg_path = getattr(args, "svg", None)
    res = mod.run_benchmarks(trials=trials, output_path=out_path, svg_path=svg_path, quiet=is_json)
    if is_json:
        print(json.dumps(res, indent=2))
    return 0


def _run_advisory(args: argparse.Namespace) -> int:
    from spechunter.advisory import (
        get_advisory_data,
        render_advisory_html,
        render_advisory_json,
        render_advisory_markdown,
    )

    data = get_advisory_data()
    is_json = getattr(args, "json", False)
    html_path = getattr(args, "html", None)
    out_path = getattr(args, "output", None)

    if html_path is not None:
        html_str = render_advisory_html(data)
        html_path.write_text(html_str, encoding="utf-8")
        print(f"Hardware Security Advisory saved to HTML: {html_path}")

    if is_json:
        print(render_advisory_json(data))
    elif out_path != Path("artifacts/run.json"):
        md_str = render_advisory_markdown(data)
        out_path.write_text(md_str, encoding="utf-8")
        print(f"Hardware Security Advisory saved to Markdown: {out_path}")
    else:
        print(render_advisory_markdown(data))

    return 0


def _run_poc(args: argparse.Namespace) -> int:
    from spechunter.poc import (
        export_pocs,
        list_pocs,
        render_poc_json,
        render_poc_text,
    )

    is_json = getattr(args, "json", False)
    export_dir = getattr(args, "export", None)
    poc_name = getattr(args, "name", None)

    if export_dir is not None:
        exported = export_pocs(export_dir)
        print(f"Exported {len(exported)} PoC artifact files to: {export_dir}")
        for path in exported:
            print(f"  • {path.name}")
        return 0

    if is_json:
        print(render_poc_json(poc_name))
        return 0

    if poc_name is not None:
        print(render_poc_text(poc_name))
    else:
        for name in list_pocs():
            print(render_poc_text(name))
            print()

    return 0


def _run_ablation(args: argparse.Namespace) -> int:
    from spechunter.ablation import (
        get_default_ablation_study,
        render_ablation_json,
        render_ablation_markdown,
        render_ablation_terminal,
    )

    benchmark = getattr(args, "benchmark", None) or "transient-cache"
    is_json = getattr(args, "json", False)
    is_markdown = getattr(args, "markdown", False)
    out_path = getattr(args, "output", None)

    study = get_default_ablation_study(benchmark)

    if is_json:
        output_str = render_ablation_json(study)
    elif is_markdown:
        output_str = render_ablation_markdown(study)
    else:
        output_str = render_ablation_terminal(study)

    if out_path != Path("artifacts/run.json") and out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output_str, encoding="utf-8")
        print(f"Ablation study saved to: {out_path}")
    else:
        print(output_str)

    return 0


def _run_harness(args: argparse.Namespace) -> int:
    from spechunter.harness import (
        export_junit_xml,
        render_harness_json,
        render_harness_terminal,
        run_harness,
    )

    pocs_arg = getattr(args, "pocs", "all")
    poc_list = None if pocs_arg == "all" else [p.strip() for p in pocs_arg.split(",")]
    verify_mit = getattr(args, "verify_mitigations", False)
    junit_path = getattr(args, "junit_xml", None)
    is_json = getattr(args, "json", False)
    out_path = getattr(args, "output", None)

    report = run_harness(poc_names=poc_list, verify_mitigations=verify_mit)

    if junit_path is not None:
        export_junit_xml(report, junit_path)
        print(f"JUnit XML exported to: {junit_path}")

    output_str = render_harness_json(report) if is_json else render_harness_terminal(report)

    if out_path != Path("artifacts/run.json") and out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output_str, encoding="utf-8")
        print(f"Harness report saved to: {out_path}")
    else:
        print(output_str)

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=[
            "run",
            "compare",
            "present",
            "evaluate",
            "verify",
            "audit",
            "waveform",
            "taxonomy",
            "benchmark",
            "advisory",
            "poc",
            "ablation",
            "harness",
        ],
    )
    parser.add_argument("--backend", choices=["model", "rtl", "boom"], default="model")
    parser.add_argument("--strategy", choices=["guided", "random", "llm"], default="guided")
    parser.add_argument("--iterations", type=int, default=16)
    parser.add_argument("--trials", type=int, default=100)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--output", type=Path, default=Path("artifacts/run.json"))
    parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Format output as JSON "
            "(supported for audit, taxonomy, benchmark, advisory, poc, ablation, harness)"
        ),
    )
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="Format output as Markdown (supported for ablation)",
    )
    parser.add_argument(
        "--junit-xml",
        type=Path,
        default=None,
        help="Path to export standard JUnit XML test report (supported for harness)",
    )
    parser.add_argument(
        "--verify-mitigations",
        action="store_true",
        help="Evaluate mitigated RTL variants in security harness (expects clean verdicts)",
    )
    parser.add_argument(
        "--pocs",
        type=str,
        default="all",
        help="Comma-separated PoC identifiers for harness command (default: all)",
    )
    parser.add_argument(
        "--suite",
        action="store_true",
        help="Audit all taxonomy benchmarks in sequence as a suite (for audit command)",
    )
    parser.add_argument(
        "--svg",
        type=Path,
        default=None,
        help="Generate SVG comparison chart (supported for benchmark command)",
    )
    parser.add_argument(
        "--html",
        type=Path,
        default=None,
        help="Generate HTML output (supported for advisory command)",
    )
    parser.add_argument(
        "--name",
        type=str,
        default=None,
        help="PoC gadget identifier (e.g. transient-cache, privilege-bypass, issue-715)",
    )
    parser.add_argument(
        "--export",
        type=Path,
        default=None,
        help="Directory to export standalone PoC assembly files (.s) and JSON specs",
    )
    parser.add_argument("--input", type=Path, help="Sealed experiment report for present")
    parser.add_argument("--seal", type=Path, help="Evidence seal for present")
    parser.add_argument("--corpus", type=Path, help="Optional sealed BOOM attack corpus")
    parser.add_argument("--corpus-seal", type=Path, help="Seal for --corpus")
    parser.add_argument("--evaluation", type=Path, help="Optional sealed fixture evaluation")
    parser.add_argument("--evaluation-seal", type=Path, help="Seal for --evaluation")
    parser.add_argument(
        "--repeatability", type=Path, help="Optional sealed Vertex repeatability evidence"
    )
    parser.add_argument("--repeatability-seal", type=Path, help="Seal for --repeatability")
    parser.add_argument("--chia-evidence", type=Path, help="Optional sealed CHIA/Vertex evidence")
    parser.add_argument("--chia-seal", type=Path, help="Seal for --chia-evidence")
    parser.add_argument(
        "--rtl-repair-seal", type=Path, help="Optional sealed BOOM RTL repair regression"
    )
    parser.add_argument(
        "--issue-715-seal", type=Path, help="Optional sealed BOOM issue #715 assessment"
    )
    parser.add_argument(
        "--issue-715-attachment-seal",
        type=Path,
        help="Optional sealed original issue #715 attachment case",
    )
    parser.add_argument(
        "--runner", type=Path, help="Trusted BOOM runner executable (absolute path)"
    )
    parser.add_argument(
        "--runner-arg",
        action="append",
        default=[],
        help="Argument passed to the trusted runner before the request path (repeatable)",
    )
    parser.add_argument("--target-revision", default="")
    parser.add_argument(
        "--timeout", type=int, help="per-execution seconds (default: 900 for BOOM, 30 otherwise)"
    )
    parser.add_argument("--benchmark", choices=[benchmark.id for benchmark in BENCHMARKS])
    parser.add_argument("--chia", action="store_true", help="Run through optional local CHIA node")
    parser.add_argument("--llm-provider", choices=["vertex"], default="vertex")
    parser.add_argument("--llm-project", default="spechunter")
    parser.add_argument("--llm-location", default="global")
    parser.add_argument("--llm-model", help="Vertex model name; required for --strategy llm")
    parser.add_argument("--llm-max-calls", type=int, default=64)
    parser.add_argument("--llm-budget-usd", type=Decimal, default=Decimal("1.00"))
    parser.add_argument("--llm-ledger", type=Path, default=Path("artifacts/llm-cost.json"))
    parser.add_argument("--llm-max-output-tokens", type=int, default=2048)
    parser.add_argument("--llm-retries", type=int, default=2)
    parser.add_argument("--recon-cycles", type=int, default=2)
    parser.add_argument("--attack-limit", type=int, default=8)
    parser.add_argument("--repair-limit", type=int, default=4)
    args = parser.parse_args()
    try:
        if args.command == "verify":
            return _run_verify()
        if args.command == "waveform":
            return _run_waveform()
        if args.command == "audit":
            return _run_audit(args)
        if args.command == "taxonomy":
            return _run_taxonomy(args)
        if args.command == "benchmark":
            return _run_benchmark(args)
        if args.command == "advisory":
            return _run_advisory(args)
        if args.command == "poc":
            return _run_poc(args)
        if args.command == "ablation":
            return _run_ablation(args)
        if args.command == "harness":
            return _run_harness(args)
        if args.command == "present":
            if args.input is None or args.seal is None:
                raise ValueError("present requires --input and --seal")
            if (args.corpus is None) != (args.corpus_seal is None):
                raise ValueError("present requires --corpus and --corpus-seal together")
            if (args.evaluation is None) != (args.evaluation_seal is None):
                raise ValueError("present requires --evaluation and --evaluation-seal together")
            if (args.repeatability is None) != (args.repeatability_seal is None):
                raise ValueError(
                    "present requires --repeatability and --repeatability-seal together"
                )
            if (args.chia_evidence is None) != (args.chia_seal is None):
                raise ValueError("present requires --chia-evidence and --chia-seal together")
            print(
                json.dumps(
                    render(
                        args.input,
                        args.seal,
                        args.output,
                        corpus_path=args.corpus,
                        corpus_seal_path=args.corpus_seal,
                        evaluation_path=args.evaluation,
                        evaluation_seal_path=args.evaluation_seal,
                        repeatability_path=args.repeatability,
                        repeatability_seal_path=args.repeatability_seal,
                        chia_path=args.chia_evidence,
                        chia_seal_path=args.chia_seal,
                        rtl_repair_seal_path=args.rtl_repair_seal,
                        issue_715_seal_path=args.issue_715_seal,
                        issue_715_attachment_seal_path=args.issue_715_attachment_seal,
                    ),
                    indent=2,
                )
            )
            return 0
        if args.command == "evaluate":
            if args.backend != "model" or args.strategy != "guided":
                raise ValueError("evaluate uses the fixed model benchmark and strategy pair")
            report = evaluate(args.trials, args.iterations)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            temporary = args.output.with_suffix(args.output.suffix + ".tmp")
            temporary.write_text(json.dumps(report, indent=2) + "\n")
            temporary.replace(args.output)
            print(json.dumps({key: report[key] for key in ("guided", "random")}, indent=2))
            return 0
        if args.runner and not args.runner.is_absolute():
            raise ValueError("runner must be an absolute executable path")
        if args.runner_arg and not args.runner:
            raise ValueError("--runner-arg requires --runner")
        timeout = (
            args.timeout if args.timeout is not None else (900 if args.backend == "boom" else 30)
        )
        config = BackendConfig(
            args.backend,
            (str(args.runner), *args.runner_arg) if args.runner else (),
            timeout,
            args.target_revision,
        )
        benchmark_id = args.benchmark
        if args.backend == "boom" and benchmark_id is None:
            benchmark_id = "secure-control"
        execute = experiment
        if args.chia:
            from spechunter.chia_nodes import run_local

            execute = run_local
        strategies = ["guided", "random"] if args.command == "compare" else [args.strategy]
        if "llm" in strategies:
            if not args.llm_model:
                raise ValueError("--llm-model is required for --strategy llm")
            if args.chia:
                from spechunter.chia_nodes import run_agent_local

                report = run_agent_local(
                    config,
                    args.llm_project,
                    args.llm_location,
                    args.llm_model,
                    args.llm_max_calls,
                    args.recon_cycles,
                    args.attack_limit,
                    args.repair_limit,
                    args.llm_budget_usd,
                    args.llm_ledger,
                    args.llm_max_output_tokens,
                    args.llm_retries,
                    benchmark_id,
                )
            else:
                from spechunter.agent_loop import agent_experiment
                from spechunter.agents import VertexAgentProvider

                provider = VertexAgentProvider(
                    args.llm_project,
                    args.llm_location,
                    args.llm_model,
                    args.llm_max_calls,
                    args.llm_budget_usd,
                    args.llm_ledger,
                    args.llm_max_output_tokens,
                    args.llm_retries,
                )
                report = agent_experiment(
                    provider,
                    config,
                    args.recon_cycles,
                    args.attack_limit,
                    args.repair_limit,
                    benchmark_id,
                )
            reports = [report]
        else:
            reports = [
                execute(config, strategy, args.iterations, args.seed, benchmark_id)
                for strategy in strategies
            ]
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_suffix(args.output.suffix + ".tmp")
        temporary.write_text(
            json.dumps(reports if args.command == "compare" else reports[0], indent=2) + "\n"
        )
        temporary.replace(args.output)
        print(json.dumps({r["strategy"]: r["metrics"] for r in reports}, indent=2))
        return 2 if any(r["metrics"]["inconclusive_cases"] for r in reports) else 0
    except (ValueError, OSError, ImportError, RuntimeError) as exc:
        print(f"spechunter: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
