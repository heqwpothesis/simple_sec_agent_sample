"""Rule definitions for identifying sources and sinks per language."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Pattern
import re


@dataclass(frozen=True)
class LanguageRules:
    source_assign: Pattern[str]
    source_inline: Pattern[str]
    sink_patterns: List[Pattern[str]]
    taint_assign: Pattern[str]
    comment: str


def compile_patterns(patterns: Iterable[str]) -> List[Pattern[str]]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


PHP_RULES = LanguageRules(
    source_assign=re.compile(
        r"\$(?P<name>[a-zA-Z0-9_]+)\s*=\s*\$_(?P<kind>GET|POST|REQUEST|COOKIE|SERVER|FILES)\b"
    ),
    source_inline=re.compile(r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b"),
    sink_patterns=compile_patterns(
        [
            r"mysqli_query",
            r"mysql_query",
            r"pdo->(query|exec|prepare)",
            r"pg_query",
            r"\b(exec|shell_exec|system|passthru|popen|proc_open|pcntl_exec|proc_close)\b",
            r"\x60.*\x60",
            r"\beval\b",
            r"\b(include|include_once|require|require_once)\b",
            r"\b(readfile|fopen|file_get_contents|file_put_contents|highlight_file|show_source)\b",
            r"\bprint(f)?\b",
            r"\becho\b",
        ]
    ),
    taint_assign=re.compile(r"\$(?P<name>[a-zA-Z0-9_]+)\s*="),
    comment="PHP DVWA rules",
)

JS_RULES = LanguageRules(
    source_assign=re.compile(
        r"(?:const|let|var)\s+(?P<name>[a-zA-Z0-9_]+)\s*=\s*req\.(?P<kind>body|query|params|cookies|headers)\b"
    ),
    source_inline=re.compile(r"req\.(body|query|params|cookies|headers)\b"),
    sink_patterns=compile_patterns(
        [
            r"\beval\b",
            r"child_process\.(exec|execFile|spawn|fork)",
            r"\bres\.(send|render|json)\b",
            r"\bdb\.\w+\.(find|insert|update|remove|aggregate)\b",
            r"collection\.(find|insert|update|remove)",
        ]
    ),
    taint_assign=re.compile(r"(?:const|let|var)\s+(?P<name>[a-zA-Z0-9_]+)\s*="),
    comment="NodeGoat / Express rules",
)

LANGUAGE_MAP = {"php": PHP_RULES, "javascript": JS_RULES, "js": JS_RULES}


def get_rules(language: str) -> LanguageRules:
    if language not in LANGUAGE_MAP:
        raise ValueError(f"No language rules for {language}")
    return LANGUAGE_MAP[language]
