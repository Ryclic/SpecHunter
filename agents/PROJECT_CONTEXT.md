# Project context

SpecHunter researches microarchitectural security using CHIA. The intended
processor target is BOOM, an open-source RISC-V core. Distinguish the current
security fixtures from actual BOOM simulation and research evidence.

## Communication

- Assume the user is technically knowledgeable, but does not have specialist
  knowledge of computer architecture or microarchitecture.
- Briefly explain field-specific concepts and expand acronyms when first introduced.
- Connect architecture details to their practical purpose and relevance to the
  project, using familiar software concepts where helpful.
- Keep explanations technically precise without overexplaining general computing
  concepts or assuming prior familiarity with processor-design tools.

## Environment

- GCP project ID: `spechunter`.
- GitHub repository: https://github.com/Ryclic/SpecHunter.

## Cloud constraints

- For now, only $300 in GCP free-trial credits is available. If more is required,
you must pause execution and state the estimate.
- Never change billing or upgrade the free trial.
- Use resources conservatively. Verify cost implications before paid operations.
- Read `docs/CLOUD.md` before cloud work. Historical setup guidance in
  `agents/GCP_INFO.md` does not override these constraints.

## Working agreements

- Work autonomously on authorized tasks and complete independent implementation
  work before deferring permission-dependent steps.
- Make changes on feature branches and submit pull requests for review.
- Use `.github/pull_request_template.md` to structure pull request descriptions,
  including when creating them through the CLI. Scale detail to the change and
  briefly mark sections that do not apply.
- Never push directly to main or merge without the user's authorization.
- See `docs/DEVELOPMENT.md` for development and validation commands.
- See `docs/ROADMAP.md` for remaining research work.
