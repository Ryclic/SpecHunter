#include "riscv_test.h"

RVTEST_RV64M
RVTEST_CODE_BEGIN
  # Entry 0 denies the aligned secret page to S/U mode. Entry 1 permits the
  # remaining address space. Neither entry is locked, so machine-mode setup
  # and the test harness retain access.
  la t0, protected_secret
  srli t0, t0, 2
  ori t0, t0, 0x1ff
  csrw pmpaddr0, t0
  li t0, -1
  csrw pmpaddr1, t0
  li t0, 0x1f18
  csrw pmpcfg0, t0
  fence rw, rw

  li s0, 0
  li a0, 0
  la t0, user_start
  csrw mepc, t0
  li t0, (3 << 11)
  csrc mstatus, t0
  mret

user_start:
  la t0, protected_secret
faulting_load:
  ld a0, 0(t0)
after_fault:
  bnez a0, test_failed
  li t0, 1
  bne s0, t0, test_failed
  RVTEST_PASS

test_failed:
  li TESTNUM, 2
  RVTEST_FAIL

  .globl mtvec_handler
mtvec_handler:
  csrr t0, mcause
  li t1, 5
  bne t0, t1, test_failed
  li s0, 1
  csrr t0, mepc
  addi t0, t0, 4
  csrw mepc, t0
  mret
RVTEST_CODE_END

RVTEST_DATA_BEGIN
  .balign 4096
protected_secret:
  .dword 0x5345435245540001
  .zero 4088
RVTEST_DATA_END
