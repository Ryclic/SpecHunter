// Small executable security state-machine fixture. This is NOT BOOM RTL.
module fixture;
  reg [7:0] ops [0:127];
  string program_path;
  integer length, secret, bug, i, value;
  reg user_mode, trained, speculative, valid;
  reg [1:0] cache_lines;
  initial begin
    if (!$value$plusargs("PROGRAM=%s", program_path) ||
        !$value$plusargs("LENGTH=%d", length) ||
        !$value$plusargs("SECRET=%d", secret) ||
        !$value$plusargs("BUG=%d", bug)) $fatal(1, "missing inputs");
    if (length < 1 || length > 128 || secret < 0 || secret > 1 || bug < 0 || bug > 2)
      $fatal(1, "invalid inputs");
    $readmemh(program_path, ops, 0, length-1);
    user_mode = 0; trained = 0; speculative = 0; valid = 0;
    cache_lines = 0; value = 0;
    for (i=0; i<length; i=i+1) begin
      case (ops[i])
        0: begin end // nop
        1: trained = 1;
        2: user_mode = 1;
        3: begin
          speculative = trained;
          valid = !user_mode || bug == 1 || (bug == 2 && speculative);
          if (valid) value = secret;
          if (user_mode) begin
            if (speculative) $display("EVENT transient-load");
            else $display("EVENT user-load");
            if (valid && !speculative) $display("ARCH %0d", value);
          end
        end
        4: if (valid && (!speculative || bug == 2)) cache_lines[value] = 1;
        5: begin speculative = 0; valid = 0; trained = 0; end
        6: if (user_mode) begin
          if (cache_lines[0]) $display("PROBE 1");
          else $display("PROBE 10");
        end
        7: begin trained = 0; speculative = 0; valid = 0; end
        default: $fatal(1, "unknown op");
      endcase
    end
    $display("DONE");
    $finish(0);
  end
endmodule
