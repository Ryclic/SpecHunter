#include <stdint.h>
#include <stdio.h>

extern void spechunter_candidate(void);

volatile uint64_t protected_secret[512] __attribute__((aligned(4096)));
volatile uint8_t probe_lines[128] __attribute__((aligned(64)));
volatile uint8_t eviction_buffer[65536] __attribute__((aligned(64)));
volatile uint64_t architectural_value;
volatile uint64_t architectural_visible;
volatile uint64_t load_faulted;
volatile uint64_t unexpected_trap;
volatile uint64_t probe_count;
volatile uint64_t probe_results[128];

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;

  for (uint64_t i = 0; i < sizeof(probe_lines); ++i)
    probe_lines[i] = (uint8_t)i;
  for (uint64_t i = 0; i < sizeof(eviction_buffer); i += 64)
    eviction_buffer[i] = (uint8_t)i;

  spechunter_candidate();

  if (architectural_visible)
    printf("SPECHUNTER ARCH %lu\n", (unsigned long)architectural_value);
  if (load_faulted)
    printf("SPECHUNTER EVENT load-access-fault\n");
  if (unexpected_trap)
    printf("SPECHUNTER EVENT unexpected-trap-%lu\n", (unsigned long)unexpected_trap);
  for (uint64_t i = 0; i < probe_count && i < 128; ++i)
    printf("SPECHUNTER PROBE %lu\n", (unsigned long)probe_results[i]);
  printf("SPECHUNTER DONE\n");
  return unexpected_trap ? 2 : 0;
}
