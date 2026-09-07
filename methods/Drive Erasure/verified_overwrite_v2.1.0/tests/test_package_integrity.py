from pathlib import Path
def test_required_files_exist():
 root=Path(__file__).parents[1]
 for rel in ["README.md","pyproject.toml","config/policy.json"]: assert (root/rel).exists()
