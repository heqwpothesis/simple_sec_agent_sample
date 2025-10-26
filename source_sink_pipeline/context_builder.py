from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from tree_sitter import Parser  # type: ignore
    from tree_sitter_languages import get_language  # type: ignore
except Exception:  # pragma: no cover - tree_sitter might be missing
    Parser = None  # type: ignore
    get_language = None  # type: ignore


PHP_FUNCTION_TYPES = {
    "function_definition",
    "method_declaration",
    "anonymous_function_creation_expression",
}
JS_FUNCTION_TYPES = {
    "function_declaration",
    "method_definition",
    "arrow_function",
    "function",
}


@dataclass
class Snippet:
    code: str
    start_line: int
    end_line: int
    sink_line: int
    source_lines: Dict[str, int]


class TreeSitterContext:
    def __init__(self, language: str) -> None:
        self.language = language
        self.parser: Optional[Parser] = None
        self._init_parser()

    def _init_parser(self) -> None:
        if Parser is None or get_language is None:
            return
        try:
            lang = get_language(self.language)
        except Exception:
            return
        parser = Parser()
        parser.set_language(lang)
        self.parser = parser

    def supports_tree_sitter(self) -> bool:
        return self.parser is not None

    def extract_function(self, code: str, line_no: int) -> Optional[Tuple[int, int]]:
        if not self.parser:
            return None
        tree = self.parser.parse(bytes(code, "utf-8"))
        target_byte = self._line_to_byte_offset(code, line_no)
        if target_byte is None:
            return None
        candidate_types = PHP_FUNCTION_TYPES if self.language == "php" else JS_FUNCTION_TYPES
        node = self._find_enclosing_node(tree.root_node, target_byte, candidate_types)
        if not node:
            return None
        return node.start_point[0] + 1, node.end_point[0] + 1

    @staticmethod
    def _find_enclosing_node(root, byte_offset: int, types: set) -> Optional[object]:
        stack = [root]
        best = None
        while stack:
            node = stack.pop()
            if node.start_byte <= byte_offset < node.end_byte:
                if node.type in types:
                    best = node
                stack.extend(node.children)
        return best

    @staticmethod
    def _line_to_byte_offset(code: str, line_no: int) -> Optional[int]:
        current_line = 1
        byte_index = 0
        encoded = code.encode("utf-8")
        while current_line < line_no and byte_index < len(encoded):
            if encoded[byte_index] == ord("\n"):
                current_line += 1
            byte_index += 1
        if current_line != line_no:
            return None
        return byte_index


class ContextBuilder:
    def __init__(self) -> None:
        self.cache: Dict[str, TreeSitterContext] = {}

    def build(self, finding: Dict[str, object]) -> Snippet:
        file_path = Path(finding["file"])  # type: ignore[index]
        language = finding["language"]  # type: ignore[index]
        sink_line = int(finding["line"])  # type: ignore[index]
        evidence: Dict[str, int] = {
            k: int(v) for k, v in (finding.get("evidence", {}) or {}).items()  # type: ignore
        }

        code = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = code.splitlines()

        context = self._get_context(language)
        if context and context.supports_tree_sitter():
            range_tuple = context.extract_function(code, sink_line)
        else:
            range_tuple = None

        if not range_tuple:
            range_tuple = self._fallback_range(lines, sink_line, language)

        start, end = range_tuple
        snippet_lines = lines[start - 1 : end]
        snippet = "\n".join(snippet_lines)
        return Snippet(
            code=snippet,
            start_line=start,
            end_line=end,
            sink_line=sink_line,
            source_lines=evidence,
        )

    def _get_context(self, language: str) -> Optional[TreeSitterContext]:
        if language not in self.cache:
            ctx = TreeSitterContext(language)
            self.cache[language] = ctx
        return self.cache[language]

    @staticmethod
    def _fallback_range(lines: List[str], sink_line: int, language: str) -> Tuple[int, int]:
        start = sink_line
        end = sink_line
        brace_balance = 0
        # search upwards for function start
        for idx in range(sink_line - 1, 0, -1):
            line = lines[idx - 1].strip()
            if language == "php":
                if line.startswith("function ") or line.startswith("class "):
                    start = idx
                    break
            else:
                if line.startswith("function ") or line.startswith("class ") or "=>" in line:
                    start = idx
                    break
        else:
            start = max(1, sink_line - 10)

        # search downwards for closing brace
        for idx in range(sink_line - 1, len(lines)):
            brace_balance += lines[idx].count("{") - lines[idx].count("}")
            if brace_balance <= 0 and idx + 1 >= sink_line and brace_balance == 0:
                end = idx + 1
                break
        if end == sink_line:
            end = min(len(lines), sink_line + 10)
        return start, max(end, sink_line)


def build_contexts(findings: List[Dict[str, object]]) -> List[Dict[str, object]]:
    builder = ContextBuilder()
    payloads: List[Dict[str, object]] = []
    for finding in findings:
        snippet = builder.build(finding)
        payloads.append(
            {
                "file": finding["file"],
                "language": finding["language"],
                "flow": finding["flow"],
                "code": snippet.code,
                "start_line": snippet.start_line,
                "end_line": snippet.end_line,
                "sink_line": snippet.sink_line,
                "sources": finding.get("sources", []),
                "source_lines": snippet.source_lines,
            }
        )
    return payloads


def build_context_file(findings_path: Path, output_path: Path) -> Path:
    findings = json.loads(findings_path.read_text())
    payloads = build_contexts(findings)
    output_path.write_text(json.dumps(payloads, indent=2))
    return output_path
