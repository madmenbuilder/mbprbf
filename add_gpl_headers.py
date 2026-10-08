#!/usr/bin/env python3
# MBPRBF — Madmen Builder for Programs on Raw Bytes Framework
# Copyright (C) 2026 Madmen3733
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""add_gpl_headers.py — добавить GPL v3 заголовок в каждый .py файл MBPRBF.

Использование:
    python add_gpl_headers.py                # обработать ./mbprbf
    python add_gpl_headers.py --dry-run      # показать, что будет изменено
    python add_gpl_headers.py path/to/dir    # обработать конкретную папку

Скрипт:
  * рекурсивно обходит все .py файлы в указанной папке,
  * пропускает файлы, где уже есть маркер "Madmen Builder for Programs",
  * добавляет GPL-заголовок в начало файла,
  * сохраняет кодировку UTF-8 и переводы строк.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

HEADER = """\
# MBPRBF — Madmen Builder for Programs on Raw Bytes Framework
# Copyright (C) 2026 Madmen3733
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

MARKER = "Madmen Builder for Programs on Raw Bytes Framework"


def has_header(text: str) -> bool:
    """Проверить, есть ли уже GPL-заголовок в первых 30 строках."""
    head = "\n".join(text.splitlines()[:30])
    return MARKER in head


def add_header(path: Path, dry_run: bool = False) -> bool:
    """Добавить заголовок. Возвращает True, если файл изменён."""
    text = path.read_text(encoding="utf-8")

    if has_header(text):
        return False

    # Если файл начинается с shebang — оставляем его первым,
    # GPL-заголовок ставим после.
    lines = text.splitlines(keepends=True)
    shebang = ""
    if lines and lines[0].startswith("#!"):
        shebang = lines[0]
        lines = lines[1:]

    new_text = shebang + HEADER + "\n" + "".join(lines)

    if not dry_run:
        # Сохраняем переводы строк как есть
        path.write_text(new_text, encoding="utf-8", newline="")

    return True


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Добавить GPL v3 заголовок во все .py файлы MBPRBF."
    )
    ap.add_argument(
        "path",
        nargs="?",
        default="mbprbf",
        help="корневая папка (по умолчанию: ./mbprbf)",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="только показать, что будет изменено",
    )
    ap.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="имена файлов/папок для пропуска (можно указывать несколько раз)",
    )
    args = ap.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"error: '{root}' не существует", file=sys.stderr)
        return 1
    if not root.is_dir():
        print(f"error: '{root}' — не папка", file=sys.stderr)
        return 1

    exclude = set(args.exclude)
    exclude.add("add_gpl_headers.py")

    changed = 0
    skipped = 0

    for py in sorted(root.rglob("*.py")):
        if py.name in exclude:
            continue
        if any(part in exclude for part in py.parts):
            continue
        if "__pycache__" in py.parts:
            continue

        try:
            modified = add_header(py, dry_run=args.dry_run)
        except UnicodeDecodeError as e:
            print(f"[skip] {py.relative_to(root)}: не UTF-8 ({e})")
            skipped += 1
            continue

        if modified:
            prefix = "[dry] " if args.dry_run else "[ok]  "
            print(f"{prefix}{py.relative_to(root)}")
            changed += 1
        else:
            skipped += 1

    print()
    print(f"changed:  {changed}")
    print(f"skipped:  {skipped}")
    print(f"dry-run:  {args.dry_run}")
    print(f"root:     {root}")

    return 0


if __name__ == "__main__":
    sys.exit(main())