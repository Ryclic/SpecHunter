# SpecHunter CHIA Composable Block Examples

This directory illustrates how to integrate **SpecHunter** as a composable security auditing and repair block within broader [CHIA](https://chialoops.ai) pipelines.

## Composable Block Usage

SpecHunter exposes `@ChiaFunction` decorated endpoints and a high-level `SpecHunterSecurityAuditBlock`:

```python
from spechunter.backends import BackendConfig
from spechunter.chia_nodes import SpecHunterSecurityAuditBlock

# Configure and instantiate the block
block = SpecHunterSecurityAuditBlock(
    config=BackendConfig(),  # Default semantic or RTL/BOOM backend
    strategy="guided",  # "guided", "random", or "llm"
    iterations=8,
    seed=0,
)

# Execute via CHIA/Ray runtime
report = block.execute(local=True)
print(f"Discovered: {report['metrics']['discovered']}")
```

## Running the Example

Ensure the `chia` extra is installed (`uv sync --extra chia`):

```bash
python examples/run_chia_pipeline.py
```
