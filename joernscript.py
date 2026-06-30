import json
import subprocess
import tempfile
import os
import sys
import ast
import re
from typing import List, Dict, Any


def run_cmd(cmd):
    print(f"[*] Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.stdout.strip():
        print(result.stdout)

    if result.returncode != 0:
        print("[!] ERROR:")
        print(result.stderr)
        raise RuntimeError(result.stderr)

    return result.stdout


def scala_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def strip_trailing_materializer(expr: str) -> str:
    """
    Remove ONE trailing materializer from an expression if present.

    Supported:
      .l
      .toList
    """
    expr = expr.rstrip()

    if expr.endswith(".toList"):
        return expr[:-7].rstrip()

    if expr.endswith(".l"):
        return expr[:-2].rstrip()

    return expr


def strip_code_exact(expr: str) -> str:
    """
    Remove all .codeExact("...") filters from a traversal.
    These are often too brittle across Joern frontends/languages.
    """
    return re.sub(r'\.codeExact\("([^"\\]|\\.)*"\)', '', expr)


def rewrite_dotted_call_names(expr: str) -> str:
    """
    Rewrite dotted call names to their bare function name because Joern often
    stores Python calls like:
      os.path.join  -> join
      pathlib.Path.open -> open
    """

    def repl(match):
        full_name = match.group(1)
        if "." in full_name:
            bare = full_name.split(".")[-1]
            return f'.name("{bare}")'
        return match.group(0)

    return re.sub(r'\.name\("([^"]+)"\)', repl, expr)


def normalize_traversal_expr(expr: str) -> str:
    """
    Apply robust normalization to a traversal expression:
      1. strip trailing .l/.toList
      2. remove brittle .codeExact(...)
      3. rewrite dotted call names to bare names
    """
    expr = strip_trailing_materializer(expr)
    expr = strip_code_exact(expr)
    expr = rewrite_dotted_call_names(expr)
    return expr.strip()


def normalize_setup_query(query_line: str) -> str:
    """
    Normalize setup lines robustly.

    Example:
      val source = cpg.call.name("read").argument.codeExact("buffer").l
        -> val source = cpg.call.name("read").argument
    """
    q = query_line.strip().rstrip(";")

    if not q.startswith("val "):
        return normalize_traversal_expr(q)

    if "=" not in q:
        return q

    left, right = q.split("=", 1)
    right = normalize_traversal_expr(right.strip())

    return f"{left.strip()} = {right}"


def strip_trailing_materializer_from_final_query(final_query: str) -> str:
    """
    Only strip trailing .l / .toList from the final flow query.
    Keep the semantic structure intact.
    """
    q = final_query.strip().rstrip(";")
    return strip_trailing_materializer(q)


def load_query_file(queries_path: str):
    """
    Accept BOTH:
    1. Strict JSON
    2. Python-style dict/list syntax

    Example accepted:
    {
      "queries": [
        "val source = ...",
        "val sink = ...",
        "sink.reachableByFlows(source)"
      ]
    }

    or

    {
      'queries': [
        'val source = ...',
        'val sink = ...',
        'sink.reachableByFlows(source)'
      ]
    }
    """
    with open(queries_path, "r", encoding="utf-8") as f:
        raw = f.read().strip()

    # Try strict JSON first
    try:
        data = json.loads(raw)
        return data
    except json.JSONDecodeError:
        pass

    # Fallback: Python literal syntax
    try:
        data = ast.literal_eval(raw)
        return data
    except Exception as e:
        raise ValueError(
            f"Could not parse query file as JSON or Python literal format: {e}"
        )


def generate_joern_script(cpg_path, queries, flow_txt):
    """
    Generate a Joern script that writes ONLY the pretty-printed flow text.
    Python will parse it into structured JSON afterwards.
    """
    if not queries or len(queries) < 1:
        raise ValueError("Expected at least 1 query in 'queries' array")

    setup_queries = queries[:-1]
    final_query_original = queries[-1].strip()

    normalized_setup_queries = [normalize_setup_query(q) for q in setup_queries]
    setup_block = "\n".join(normalized_setup_queries)

    final_query_no_materializer = strip_trailing_materializer_from_final_query(final_query_original)

    script = f'''
importCpg("{scala_escape(cpg_path)}")

{setup_block}

val prettyFlows = {final_query_no_materializer}.p

val flowText =
  if (prettyFlows.isEmpty) {{
    "No flows found."
  }} else {{
    prettyFlows.mkString("\\n\\n====================\\n\\n")
  }}

flowText #> "{scala_escape(flow_txt)}"

println("[+] Normalized setup queries:")
{chr(10).join([f'println("    {scala_escape(q)}")' for q in normalized_setup_queries])}

println("[+] Final flow query:")
println("    {scala_escape(final_query_no_materializer)}")

println("[+] Flow text saved to: {scala_escape(flow_txt)}")
'''
    return script, normalized_setup_queries, final_query_no_materializer


def parse_joern_table(table_text: str) -> List[Dict[str, Any]]:
    """
    Parse a single Joern ASCII table into a list of node dicts.

    Example columns:
      nodeType | tracked | line | method | file
    """
    lines = [line.rstrip("\n") for line in table_text.splitlines() if line.strip()]

    table_lines = [
        ln for ln in lines
        if ln.startswith("│") or ln.startswith("├") or ln.startswith("┌") or ln.startswith("└")
    ]

    if not table_lines:
        return []

    content_rows = [ln for ln in table_lines if ln.startswith("│")]

    if len(content_rows) < 2:
        return []

    header_row = content_rows[0]
    headers = [cell.strip() for cell in header_row.strip("│").split("│")]

    data_rows = content_rows[1:]

    parsed_nodes = []
    for row in data_rows:
        cells = [cell.strip() for cell in row.strip("│").split("│")]

        if len(cells) != len(headers):
            continue

        node = dict(zip(headers, cells))

        if "line" in node:
            try:
                node["line"] = int(node["line"])
            except Exception:
                pass

        parsed_nodes.append(node)

    return parsed_nodes


def split_flow_tables(flow_text: str) -> List[str]:
    """
    Split the Joern pretty output into separate flow tables.
    """
    if not flow_text or flow_text.strip() == "No flows found.":
        return []

    parts = [p.strip() for p in flow_text.split("====================") if p.strip()]
    return parts


def looks_like_call(tracked: str) -> bool:
    """
    Heuristic: treat as a call-like expression if it contains (...) pattern.
    """
    if not isinstance(tracked, str):
        return False
    return "(" in tracked and ")" in tracked


def node_key_basic(node: Dict[str, Any]):
    return (
        str(node.get("tracked", "")).strip(),
        node.get("line", ""),
        str(node.get("method", "")).strip(),
        str(node.get("file", "")).strip(),
    )


def prefer_better_node(existing: Dict[str, Any], candidate: Dict[str, Any]) -> Dict[str, Any]:
    """
    If two nodes represent the same semantic location/tracked text, choose the better one.

    Preference:
      1. Call over Identifier if same tracked text
      2. Otherwise keep existing
    """
    e_type = existing.get("nodeType", "")
    c_type = candidate.get("nodeType", "")

    if e_type == c_type:
        return existing

    if c_type == "Call" and e_type == "Identifier":
        return candidate

    return existing


def compact_flow_nodes(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Reduce noisy Joern path nodes into a cleaner LLM-friendly path.

    Steps:
      1. Remove exact adjacent duplicates
      2. Merge adjacent semantic duplicates (same tracked/line/method/file)
         and prefer Call over Identifier
      3. Global dedup while preserving order
    """
    if not nodes:
        return []

    # Step 1: remove exact adjacent duplicates
    step1 = []
    prev_exact = None
    for n in nodes:
        exact_key = (
            n.get("nodeType", ""),
            str(n.get("tracked", "")).strip(),
            n.get("line", ""),
            str(n.get("method", "")).strip(),
            str(n.get("file", "")).strip(),
        )
        if exact_key != prev_exact:
            step1.append(n)
        prev_exact = exact_key

    # Step 2: merge adjacent semantic duplicates (same tracked/line/method/file)
    step2 = []
    for n in step1:
        if not step2:
            step2.append(n)
            continue

        prev = step2[-1]
        if node_key_basic(prev) == node_key_basic(n):
            step2[-1] = prefer_better_node(prev, n)
        else:
            step2.append(n)

    # Step 3: global dedup while preserving order
    seen = set()
    step3 = []
    for n in step2:
        k = (
            n.get("nodeType", ""),
            str(n.get("tracked", "")).strip(),
            n.get("line", ""),
            str(n.get("method", "")).strip(),
            str(n.get("file", "")).strip(),
        )
        if k not in seen:
            seen.add(k)
            step3.append(n)

    return step3


def flow_signature(nodes: List[Dict[str, Any]]) -> str:
    """
    Build a canonical signature for semantic flow deduplication.
    """
    parts = []
    for n in nodes:
        parts.append("||".join([
            str(n.get("nodeType", "")).strip(),
            str(n.get("tracked", "")).strip(),
            str(n.get("line", "")).strip(),
            str(n.get("method", "")).strip(),
            str(n.get("file", "")).strip(),
        ]))
    return "\n".join(parts)


def dedup_and_compact_flows(raw_flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Compact nodes inside each flow, then deduplicate semantically identical flows.
    """
    deduped = []
    seen = set()

    for flow in raw_flows:
        compacted_nodes = compact_flow_nodes(flow.get("nodes", []))
        sig = flow_signature(compacted_nodes)

        if sig in seen:
            continue

        seen.add(sig)

        new_flow = {
            "flow_id": len(deduped) + 1,
            "nodes": compacted_nodes
        }

        deduped.append(new_flow)

    return deduped


def build_structured_json(source_file: str,
                          cpg_path: str,
                          original_queries: List[str],
                          normalized_setup_queries: List[str],
                          final_query: str,
                          flow_text: str) -> Dict[str, Any]:
    """
    Build LLM-friendly structured JSON from Joern pretty-printed flow tables.
    """
    raw_tables = split_flow_tables(flow_text)

    raw_flows = []
    for idx, table in enumerate(raw_tables, start=1):
        nodes = parse_joern_table(table)
        raw_flows.append({
            "flow_id": idx,
            "nodes": nodes
        })

    deduped = dedup_and_compact_flows(raw_flows)

    result = {
        "source_file": source_file,
        "cpg_path": cpg_path,
        "queries": original_queries,
        "normalized_queries": normalized_setup_queries + [final_query],
        "flow_count_raw": len(raw_flows),
        "flow_count_unique": len(deduped),
        "flows": deduped
    }

    return result


def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python main.py <source_file> <queries_json> [cpg_path] [flow_txt] [snippet_json]")
        print("")
        print("Example:")
        print("  python main.py code.java queries.json cpg.bin flows.txt snippet.json")
        sys.exit(1)

    source_file = sys.argv[1]
    queries_json_path = sys.argv[2]
    cpg_path = sys.argv[3] if len(sys.argv) > 3 else "cpg.bin"
    flow_txt = sys.argv[4] if len(sys.argv) > 4 else "flows.txt"
    snippet_json = sys.argv[5] if len(sys.argv) > 5 else "snippet.json"

    # Load query file
    data = load_query_file(queries_json_path)

    if "queries" not in data or not isinstance(data["queries"], list):
        raise ValueError("Input query file must contain a 'queries' array/list")

    queries = data["queries"]

    if len(queries) < 1:
        raise ValueError("Expected at least 1 query string in 'queries'")

    # 1. Parse source into CPG and save it to the specified path
    run_cmd(f'joern-parse "{source_file}" --output "{cpg_path}"')

    # 2. Generate temp Joern script
    script_content, normalized_setup_queries, final_query_no_materializer = generate_joern_script(
        cpg_path=cpg_path,
        queries=queries,
        flow_txt=flow_txt
    )

    with tempfile.NamedTemporaryFile(delete=False, suffix=".sc", mode="w", encoding="utf-8") as tmp_script:
        tmp_script.write(script_content)
        script_path = tmp_script.name

    try:
        # 3. Run Joern script
        run_cmd(f'joern --script "{script_path}"')
        print("[+] Joern flow extraction completed.")

        # 4. Read flow text
        if os.path.exists(flow_txt):
            with open(flow_txt, "r", encoding="utf-8") as f:
                flow_text = f.read()
        else:
            flow_text = "No flows found."

        # 5. Convert pretty tables -> structured JSON
        structured = build_structured_json(
            source_file=source_file,
            cpg_path=cpg_path,
            original_queries=queries,
            normalized_setup_queries=normalized_setup_queries,
            final_query=final_query_no_materializer,
            flow_text=flow_text
        )

        # 6. Write structured JSON
        with open(snippet_json, "w", encoding="utf-8") as f:
            json.dump(structured, f, indent=2, ensure_ascii=False)

        print(f"[+] Structured JSON saved to: {snippet_json}")
        print("[+] Automation completed successfully.")

    finally:
        if os.path.exists(script_path):
            os.remove(script_path)


if __name__ == "__main__":
    main()
