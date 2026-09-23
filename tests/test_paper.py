import re
from pathlib import Path


def test_paper_pdf_exists_and_is_four_pages():
    pdf_path = Path(__file__).parents[1] / "paper/spechunter_micro2026.pdf"
    assert pdf_path.is_file(), f"Expected paper PDF at {pdf_path}"
    content = pdf_path.read_bytes()
    pages = len(re.findall(rb"/Type\s*/Page\b", content))
    assert pages == 4, f"Hackathon paper must be exactly 4 pages, got {pages}"


def test_paper_latex_and_bib_exist():
    tex_path = Path(__file__).parents[1] / "paper/spechunter.tex"
    bib_path = Path(__file__).parents[1] / "paper/references.bib"
    typ_path = Path(__file__).parents[1] / "paper/spechunter.typ"
    assert tex_path.is_file()
    assert bib_path.is_file()
    assert typ_path.is_file()


def test_paper_figures_exist():
    fig_dir = Path(__file__).parents[1] / "paper/figures"
    assert (fig_dir / "fig1_architecture.svg").is_file()
    assert (fig_dir / "fig2_boom_pipeline.svg").is_file()
    assert (fig_dir / "fig3_eval_chart.svg").is_file()
