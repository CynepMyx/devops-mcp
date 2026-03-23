import ast
import pathlib
import sys

errors = []
for f in pathlib.Path(".").rglob("*.py"):
    if "_wip" in f.parts or "scripts" in f.parts:
        continue
    try:
        ast.parse(f.read_text())
    except SyntaxError as e:
        errors.append(f"{f}: {e}")

if errors:
    for e in errors:
        print("SYNTAX ERROR:", e)
    sys.exit(1)

checked = len([f for f in pathlib.Path(".").rglob("*.py")
               if "_wip" not in f.parts and "scripts" not in f.parts])
print(f"Syntax OK: {checked} files checked")
