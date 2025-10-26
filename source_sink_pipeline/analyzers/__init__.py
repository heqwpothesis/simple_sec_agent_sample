"""Analyzer registry."""

from .php import PHPAnalyzer
from .javascript import JavaScriptAnalyzer

ANALYZERS = {
    "php": PHPAnalyzer,
    "javascript": JavaScriptAnalyzer,
    "js": JavaScriptAnalyzer,
}


def get_analyzer(language: str):
    if language not in ANALYZERS:
        raise ValueError(f"No analyzer for language {language}")
    return ANALYZERS[language]
