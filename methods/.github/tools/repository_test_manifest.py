from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in sorted(ROOT.rglob("tests")):
    if ".git" not in p.parts and p.is_dir():
        print(p.relative_to(ROOT))
