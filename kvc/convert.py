from pathlib import Path

EXTENSIONS = {".asm", ".c", ".cpp", ".h", ".rc", ".txt", ".inc", ".def", ".bat"}

for path in Path(".").rglob("*"):
    if path.suffix.lower() not in EXTENSIONS:
        continue

    raw = path.read_bytes()

    # Juz UTF-8 (z BOM lub bez) - nie dotykamy
    try:
        raw.decode("utf-8")
        print(f"[UTF-8] {path.name}")
        continue
    except UnicodeDecodeError:
        pass

    # ANSI (cp1250) - konwertujemy
    try:
        path.write_bytes(raw.decode("cp1250").encode("utf-8"))
        print(f"[CONV]  {path.name}")
    except Exception as e:
        print(f"[ERR]   {path.name} -> {e}")