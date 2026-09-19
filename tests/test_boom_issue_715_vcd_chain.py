import importlib.util
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "tools/boom/scan_issue_715_vcd.py"
SPEC = importlib.util.spec_from_file_location("issue_715_vcd", SCRIPT)
SCANNER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(SCANNER)


def chain(*, source_cycle=30, sink_cycle=32, fault_cycle=40, resolution_cycle=50, mask="0x1"):
    return SCANNER._witness_flags(
        10,
        {0xD010028E00: 12, 0xD010028E04: 13},
        [{"cycle": source_cycle, "branch_mask": "0x1"}],
        [{"cycle": sink_cycle, "branch_mask": mask}],
        [{"cycle": fault_cycle, "branch_mask": "0x1"}],
        [{"cycle": resolution_cycle}],
    )


def test_ordered_shared_branch_window_is_witnessed():
    assert chain() == (True, True)
    assert chain(mask="0x3") == (True, True)


def test_unrelated_events_cannot_form_a_witness():
    assert chain(mask="0x2") == (False, False)
    assert chain(fault_cycle=51) == (True, False)
    assert chain(source_cycle=9) == (False, False)
    assert chain(sink_cycle=51) == (False, False)
    assert SCANNER._witness_flags(
        10,
        {0xD010028E00: 12, 0xD010028E04: 31},
        [{"cycle": 30, "branch_mask": "0x1"}],
        [{"cycle": 32, "branch_mask": "0x1"}],
        [{"cycle": 40, "branch_mask": "0x1"}],
        [{"cycle": 50}],
    ) == (True, False)
    assert SCANNER._witness_flags(
        10,
        {0xD010028E00: 12, 0xD010028E04: 13},
        [{"cycle": 30, "branch_mask": "0x1"}],
        [{"cycle": 32, "branch_mask": "0x1"}],
        [{"cycle": 40, "branch_mask": "0x2"}],
        [{"cycle": 50}],
    ) == (True, False)


def test_later_valid_chain_is_not_hidden_by_earlier_unrelated_request():
    dataflow, witness = SCANNER._witness_flags(
        10,
        {0xD010028E00: 12, 0xD010028E04: 13},
        [{"cycle": 30, "branch_mask": "0x1"}],
        [{"cycle": 20, "branch_mask": "0x2"}, {"cycle": 32, "branch_mask": "0x1"}],
        [{"cycle": 40, "branch_mask": "0x1"}],
        [{"cycle": 50}],
    )
    assert (dataflow, witness) == (True, True)


def test_later_misprediction_cannot_extend_first_branch_window():
    assert SCANNER._witness_flags(
        10,
        {0xD010028E00: 12, 0xD010028E04: 13},
        [{"cycle": 30, "branch_mask": "0x1"}],
        [{"cycle": 32, "branch_mask": "0x1"}],
        [{"cycle": 40, "branch_mask": "0x1"}],
        [{"cycle": 50}, {"cycle": 20}],
    ) == (False, False)
