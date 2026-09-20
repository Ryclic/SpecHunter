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


def test_reused_destination_and_load_queue_slot_require_same_rob_entry():
    dispatches = [
        {
            "cycle": 10,
            "pdst": "0x15",
            "prs1": "0x12",
            "ldq_idx": "0x1",
            "rob_idx": "0x1",
            "branch_mask": "0x1",
            "pc_lob": "0x4",
        }
    ]
    match = SCANNER._match_dispatch(
        dispatches,
        cycle=12,
        pdst="0x15",
        prs1="0x12",
        ldq_idx="0x1",
        rob_idx="0x1",
        branch_mask=1,
    )
    assert match == dispatches[0]
    assert (
        SCANNER._match_dispatch(
            dispatches,
            cycle=20,
            pdst="0x15",
            prs1="0x12",
            ldq_idx="0x1",
            rob_idx="0x9",
            branch_mask=1,
        )
        is None
    )


def test_dependent_tlb_request_requires_valid_matching_lsu_rob_identity():
    dispatch = {
        "cycle": 10,
        "pdst": "0x15",
        "ldq_idx": "0x1",
        "rob_idx": "0x1",
        "branch_mask": "0x1",
    }
    request = {
        "cycle": 12,
        "pdst": "0x15",
        "ldq_idx": "0x1",
        "vaddr": "0x59f",
        "branch_mask": "0x1",
    }
    exe = {**request, "rob_idx": "0x1"}
    verify = SCANNER._dependent_tlb_requests
    assert verify([request], [dispatch], [exe]) == [request]
    assert verify([request], [dispatch], []) == []
    assert verify([request], [dispatch], [{**exe, "rob_idx": "0x9"}]) == []
    assert verify([request], [dispatch], [{**exe, "cycle": 13}]) == []
    assert verify([request], [dispatch], [{**exe, "vaddr": "0x600"}]) == []
    assert verify([request], [dispatch], [{**exe, "branch_mask": "0x2"}]) == []

    # A genuine dependent request after branch resolution must still not be
    # classified as a transient dataflow observation.
    late_request = {**request, "cycle": 51}
    late_exe = {**exe, "cycle": 51}
    assert verify([late_request], [dispatch], [late_exe]) == [late_request]
    assert SCANNER._witness_flags(
        1,
        {0xD010028E00: 2, 0xD010028E04: 3},
        [{"cycle": 11, "branch_mask": "0x1"}],
        [late_request],
        [{"cycle": 30, "branch_mask": "0x1"}],
        [{"cycle": 40}],
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
        "$scope module core $end\n"
        "$var wire 1 s io_lsu_ld_miss $end\n"
        "$var wire 1 t iregister_read_io_iss_valids_0 $end\n"
        "$scope module mem_issue_unit $end\n"
        "$var wire 1 a io_dis_uops_0_valid $end\n"
        "$var wire 6 b io_dis_uops_0_bits_pc_lob $end\n"
        "$var wire 6 c io_dis_uops_0_bits_pdst $end\n"
        "$var wire 6 d io_dis_uops_0_bits_prs1 $end\n"
        "$var wire 1 e io_dis_uops_0_bits_prs1_busy $end\n"
        "$var wire 4 f io_dis_uops_0_bits_ldq_idx $end\n"
        "$var wire 4 g io_dis_uops_0_bits_br_mask $end\n"
        "$var wire 5 u io_dis_uops_0_bits_rob_idx $end\n"
        "$var wire 1 h io_iss_valids_0 $end\n"
        "$var wire 6 i io_iss_uops_0_pdst $end\n"
        "$var wire 6 j io_iss_uops_0_prs1 $end\n"
        "$var wire 4 k io_iss_uops_0_ldq_idx $end\n"
        "$var wire 5 v io_iss_uops_0_rob_idx $end\n"
        "$var wire 4 l io_iss_uops_0_br_mask $end\n"
        "$var wire 1 r io_iss_uops_0_iw_p1_poisoned $end\n"
        "$upscope $end\n"
        "$upscope $end\n"
        "$scope module lsu $end\n"
        "$var wire 1 % io_core_spec_ld_wakeup_0_valid $end\n"
        "$var wire 6 & io_core_spec_ld_wakeup_0_bits $end\n"
        "$var wire 1 ' fired_load_incoming_REG $end\n"
        "$var wire 1 ( mem_tlb_miss_0 $end\n"
        "$var wire 1 ) dmem_req_fire_0 $end\n"
        "$var wire 1 m io_core_exe_0_req_valid $end\n"
        "$var wire 6 n io_core_exe_0_req_bits_uop_pdst $end\n"
        "$var wire 4 o io_core_exe_0_req_bits_uop_ldq_idx $end\n"
        "$var wire 5 w io_core_exe_0_req_bits_uop_rob_idx $end\n"
        "$var wire 4 p io_core_exe_0_req_bits_uop_br_mask $end\n"
        "$var wire 40 q io_core_exe_0_req_bits_addr $end\n"
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
