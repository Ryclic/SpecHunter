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


def test_predicted_pc_alone_is_not_a_frontend_observation(tmp_path):
    path = tmp_path / "predictor-only.vcd"
    path.write_text(
        "$scope module TOP $end\n"
        "$scope module boom_tile $end\n"
        "$scope module frontend $end\n"
        "$var wire 40 ! s0_vpc $end\n"
        "$scope module fb $end\n"
        '$var wire 40 " pc_2 $end\n'
        "$var wire 1 # io_enq_valid $end\n"
        "$upscope $end\n"
        "$scope module predictor $end\n"
        "$var wire 40 $ guessed_pc $end\n"
        "$upscope $end\n"
        "$upscope $end\n"
        "$scope module lsu $end\n"
        "$var wire 1 % io_core_spec_ld_wakeup_0_valid $end\n"
        "$var wire 6 & io_core_spec_ld_wakeup_0_bits $end\n"
        "$var wire 1 ' fired_load_incoming_REG $end\n"
        "$var wire 1 ( mem_tlb_miss_0 $end\n"
        "$var wire 1 ) dmem_req_fire_0 $end\n"
        "$upscope $end\n"
        "$upscope $end\n"
        "$enddefinitions $end\n"
        "#0\n"
        "b0 !\n"
        'b0 "\n'
        "0#\n"
        "#2\n"
        f"b{SCANNER.BRANCH_PC:b} $\n"
        "#4\n"
        "b0 $\n"
        "#6\n"
    )
    witness = SCANNER.scan(path)
    assert witness["branch_frontend_pc_cycle"] is None
    assert all(cycle is None for cycle in witness["gadget_frontend_pc_cycles"].values())
