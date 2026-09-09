SpecHunter: Agentic Discovery and Repair of Microarchitectural Security Vulnerabilities
Overview
Modern out-of-order processors contain complex interactions between speculation, privilege enforcement, and microarchitectural state that can lead to subtle security vulnerabilities. Manually constructing tests for these behaviors requires significant architecture and security expertise, while conventional fuzzing often lacks the semantic guidance necessary to explore meaningful attack scenarios.
Our project proposes SpecHunter, a reusable CHIA loop that autonomously acts as a security red team for an open-source RISC-V processor. SpecHunter will target the BOOM out-of-order core and search for instruction sequences that violate security invariants involving speculative execution and privilege isolation. As such, our project would address the track for discovering/resolving architectural and microarchitectural bugs, specifically with a focus on microarchitectural security.
Our central research question is: Can an agent effectively discover and assist in repairing microarchitectural security violations?
Methodology
SpecHunter will implement a closed-loop workflow in CHIA consisting of four, separate agent stages:
(Recon Agent) Security hypothesis generation. Given a security invariant and architectural context, an LLM agent generates plausible attack scenarios. Initial invariants will focus on properties such as preventing lower-privilege software from observing protected state and ensuring speculative execution does not leave security-sensitive observable effects.
(Attacker Agent) Adversarial program generation and execution. The agent translates each hypothesis into small RISC-V assembly programs and executes them using BOOM through Verilator/Chipyard. Spike will provide an architectural reference where appropriate. Execution traces and relevant microarchitectural state will be collected for analysis.
(Validator Agent) Feedback-driven attack refinement. The agent examines simulation results and iteratively modifies instruction sequences, branch behavior, memory layout, cache state, and privilege transitions. Rather than randomly fuzzing programs, SpecHunter uses simulator feedback to guide subsequent experiments toward behaviors likely to violate the target property. Successful cases are automatically minimized into compact counterexamples.
(Repair Agent) Diagnosis and repair. For discovered violations, an agent analyzes the relevant RTL and execution trace, identifies candidate root causes, and proposes a patch or mitigation. The original exploit and regression tests are then rerun to determine whether the proposed modification eliminates the violation.
To evaluate the loop systematically even if no previously unknown BOOM vulnerability is discovered, we will create a small benchmark containing seeded and known security bugs involving privilege checks and speculative state. We will measure vulnerability discovery rate, number of agent iterations required, counterexample size, false positives, and successful automated repairs.
Expected Results
We expect to deliver:
An open-source, reusable CHIA security-auditing loop for RISC-V processors.
A benchmark of security-oriented BOOM bugs and corresponding adversarial programs.
Quantitative evaluation comparing agent-guided vulnerability discovery against unguided/random test generation.
Automatically minimized proof-of-concept programs for discovered violations.
Case studies showing whether SpecHunter can identify the relevant RTL and propose verified fixes.
A successful result would demonstrate that agentic workflows can perform not only functional hardware verification, but also goal-directed adversarial security analysis.
Estimated Compute/API Cost
We request $750 in credits. We estimate approximately $250 for Gemini API usage across hypothesis generation, trace analysis, test refinement, and RTL diagnosis; $400 for GCP CPU instances running parallel Verilator/Chipyard simulations and experiment sweeps; and $100 for storage, artifact generation, and higher-cost exploratory runs. The loop will support parallel execution so additional compute can primarily be used to increase the number of security experiments evaluated
