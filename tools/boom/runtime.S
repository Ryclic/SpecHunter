  .section .text
  .align 2
  .globl spechunter_trap_handler
spechunter_trap_handler:
  csrr t0, mcause
  li t1, 5
  beq t0, t1, .Lload_fault
  li t1, 8
  beq t0, t1, .Luser_ecall

  la t1, unexpected_trap
  sd t0, 0(t1)
  j .Lreturn_machine

.Lload_fault:
  la t0, load_faulted
  li t1, 1
  sd t1, 0(t0)
  la t0, spechunter_after_fault
  csrw mepc, t0
  mret

.Luser_ecall:
.Lreturn_machine:
  li t0, (3 << 11)
  csrs mstatus, t0
  la t0, spechunter_machine_resume
  csrw mepc, t0
  mret
