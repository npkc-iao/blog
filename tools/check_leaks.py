"""Проверка публичного репо на утечки внутренней информации.

Запускается в CI на каждый push/PR и локально перед коммитом:
    py -3 tools/check_leaks.py
INPUT: все текстовые файлы репозитория
OUTPUT: список подозрительных строк в stdout, код возврата 1 при находках
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", "_site", ".jekyll-cache", "tools"}
TEXT_EXT = {".md", ".markdown", ".html", ".yml", ".yaml", ".py", ".txt", ".json", ".css", ".js", ".csv"}

# (описание, регулярка); регистр не учитывается
RULES = [
    ("токен/вебхук", r"rest/\d+/[a-z0-9]{10,}|gsk_[a-z0-9]{20,}|\d{9,10}:AA[\w-]{33}|y0_[\w-]{30,}|ghp_[a-z0-9]{30,}|github_pat_\w{30,}"),
    ("пароль", r"(password|passwd|парол[ья])\s*[:=]\s*['\"][^'\"]{4,}['\"]"),
    ("номер ОМС (16 цифр)", r"(?<!\d)\d{16}(?!\d)"),
    ("СНИЛС", r"\b\d{3}-\d{3}-\d{3} ?\d{2}\b"),
    ("внутренний IP", r"\b(10|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(\.\d{1,3})?\b"),
    ("внутренние хосты", r"datalake|emias|npcmr|mosmed|\bml\d\b|\bpc\d{3}\b|noute\d+"),
    ("VPN и доступы", r"checkpoint|softether|trac\.exe|amnezia"),
    ("имена схем и витрин", r"\bdwh_\w+|\bdit_dm\b|\bdata_views\b|\bv_eris_\w+|\bv_mosdoctor\w*|\bv_route_\w+|\bkis\.\w+"),
    ("служебные id", r"\bassignment_\w+_id\b|\bmu_id\b|\bpatient_id\b|chat\d{5,}"),
    ("Битрикс/вебхуки", r"bitrix24|/rest/\d+"),
]

COMPILED = [(name, re.compile(rx, re.IGNORECASE)) for name, rx in RULES]


def iter_files():
    for p in ROOT.rglob("*"):
        if p.is_file() and p.suffix.lower() in TEXT_EXT and not SKIP_DIRS & set(p.relative_to(ROOT).parts):
            yield p


def main() -> int:
    found = 0
    for path in iter_files():
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for num, line in enumerate(lines, 1):
            for name, rx in COMPILED:
                m = rx.search(line)
                if m:
                    found += 1
                    rel = path.relative_to(ROOT).as_posix()
                    print(f"{rel}:{num}: [{name}] «{m.group(0)}»")
                    if "GITHUB_ACTIONS" in __import__("os").environ:
                        print(f"::error file={rel},line={num}::{name}: {m.group(0)}")
    if found:
        print(f"\nНайдено подозрительных мест: {found}. Публиковать нельзя, пока не вычищено.")
        return 1
    print("Утечек не найдено.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
