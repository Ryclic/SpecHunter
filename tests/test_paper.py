from pathlib import Path

PAPER = Path(__file__).parents[1] / "paper"


def test_paper_sources_and_pdf_exist():
    assert (PAPER / "main.tex").is_file()
    assert (PAPER / "main.bib").is_file()
    assert (PAPER / "spechunter_a3_2026.pdf").read_bytes().startswith(b"%PDF")


def test_paper_acknowledges_ai_assistance():
    assert "\\section*{AI Assistance Disclosure}" in (PAPER / "main.tex").read_text()


def test_paper_uses_only_sealed_results():
    source = (PAPER / "main.tex").read_text()
    for claim in ("1091", "HSA-CERT", "CVSS", "89{,}200", "89,200", "0.05\\%"):
        assert claim not in source, claim
    assert "security\\_fix\\_validated" in source
