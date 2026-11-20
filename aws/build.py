#!/usr/bin/env python3
"""Inline src/*.py into template.src.yaml -> quick-demo-env.yaml (checks the 4096-char CFN limit)."""
import pathlib
here = pathlib.Path(__file__).parent
t = (here / "template.src.yaml").read_text()
for tag, f in [("__SEED__", "seed.py"), ("__MCP__", "mcp.py")]:
    code = (here / "src" / f).read_text()
    assert len(code) <= 4096, f"{f} is {len(code)} chars (CFN inline limit 4096)"
    t = t.replace(tag, "\n".join(("          " + l) if l else "" for l in code.rstrip("\n").split("\n")))
(here / "quick-demo-env.yaml").write_text(t)
print("wrote quick-demo-env.yaml")
