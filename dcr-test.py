#!/usr/bin/env python3
"""
dcr_preview.py - see what your data collection rule (DCR) will write to the table,
before you deploy anything.

Give it a DCR and a few sample events (for example, copied from the Events tab of
"Test Connector" in the Microsoft Sentinel extension for VS Code). It writes KQL you
can paste into Log Analytics (Logs) or Advanced hunting:

  1. Preview query - builds `source` from your events, typed exactly as the DCR's
     stream declaration types them, then runs your transformKql unchanged.
  2. Schema check  - compares the transformation's output columns and types with
     the destination table (from a table file, or the live table in the workspace).

The DCR can be any JSON that contains one: a CCF *_DCR.json, a raw DCR resource,
an ARM template, or `az monitor data-collection rule show` output.

Usage:
  python dcr_preview.py --dcr MyConnector_DCR.json --events events.json
  python dcr_preview.py --dcr dcr.json --events response.json --events-path '$.items' -o preview.kql

Python 3.8+, no dependencies.
"""
import argparse
import glob
import json
import math
import os
import re
import sys

# DCR stream / table column type -> KQL conversion function and getschema type name
CONVERT = {
    "string": "tostring", "int": "toint", "long": "tolong", "real": "toreal",
    "boolean": "tobool", "bool": "tobool", "datetime": "todatetime",
    "dynamic": None, "guid": "toguid", "timespan": "totimespan",
}
SCHEMA_TYPE = {"boolean": "bool"}
SYSTEM_COLUMNS = ("TenantId", "SourceSystem", "Type", "MG", "ManagementGroupName")


# ---------------------------------------------------------------- loading helpers
def load_json_lenient(path):
    """Load a JSON document, JSON Lines, or several concatenated JSON values."""
    with open(path, encoding="utf-8-sig") as f:
        text = f.read().strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    values, dec, i = [], json.JSONDecoder(), 0
    while i < len(text):
        while i < len(text) and text[i] in " \t\r\n,":
            i += 1
        if i >= len(text):
            break
        try:
            value, i = dec.raw_decode(text, i)
        except json.JSONDecodeError as e:
            sys.exit(f"error: {path} is not valid JSON or JSON Lines ({e})")
        values.append(value)
    return values


def get_ci(d, key, default=None):
    """Case-insensitive dict lookup (DCR exports and templates vary in casing)."""
    if not isinstance(d, dict):
        return default
    for k, v in d.items():
        if k.lower() == key.lower():
            return v
    return default


def walk(obj):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk(v)


def find_dcrs(doc):
    """Every object that has both streamDeclarations and dataFlows."""
    found = []
    for node in walk(doc):
        props = get_ci(node, "properties") if isinstance(get_ci(node, "properties"), dict) else node
        sd, df = get_ci(props, "streamDeclarations"), get_ci(props, "dataFlows")
        if isinstance(sd, dict) and isinstance(df, list) and all(id(props) != id(f["props"]) for f in found):
            found.append({"name": get_ci(node, "name") or "(unnamed DCR)", "props": props})
    return found


def find_tables(doc):
    """Table schemas: objects with schema.columns (Tables API / ARM / CCF table files)."""
    tables = {}
    for node in walk(doc):
        schema = get_ci(node, "schema")
        if isinstance(schema, dict) and isinstance(get_ci(schema, "columns"), list):
            name = get_ci(schema, "name") or get_ci(node, "name")
            if isinstance(name, str) and not name.startswith("["):
                cols = [(get_ci(c, "name"), str(get_ci(c, "type", "string")).lower())
                        for c in get_ci(schema, "columns") if isinstance(c, dict) and get_ci(c, "name")]
                tables[name.lower()] = (name, cols)
    return tables


def json_path(doc, path):
    """Small JSONPath subset: $, $.a.b, $['a'], $.a[*], $.a[0]."""
    if not path or path.strip() == "$":
        return doc
    tokens = re.findall(r"\.([^.\[\]]+)|\[['\"](.+?)['\"]\]|\[(\*|\d+)\]", path.strip().lstrip("$"))
    current = [doc]
    for key, quoted, index in tokens:
        nxt = []
        for c in current:
            if key or quoted:
                v = get_ci(c, key or quoted) if isinstance(c, dict) else None
                if v is not None:
                    nxt.append(v)
            elif index == "*" and isinstance(c, list):
                nxt.extend(c)
            elif isinstance(c, list) and int(index) < len(c):
                nxt.append(c[int(index)])
        current = nxt
    if len(current) == 1:
        return current[0]
    return current


def to_events(doc, path):
    data = json_path(doc, path) if path else doc
    if isinstance(data, dict) and not path:
        lists = [v for v in data.values() if isinstance(v, list) and v and all(isinstance(x, dict) for x in v)]
        if len(lists) == 1 and len(data) <= 5:
            print("note: events look wrapped in a response object; using its only list of objects "
                  "(use --events-path to choose explicitly)", file=sys.stderr)
            data = lists[0]
    events = data if isinstance(data, list) else [data]
    events = [e for e in events if isinstance(e, dict)]
    if not events:
        sys.exit("error: no JSON objects found in the events file (try --events-path, e.g. '$.items')")
    return events


def poller_events_path(path):
    for node in walk(load_json_lenient(path)):
        paths = get_ci(get_ci(node, "response") or {}, "eventsJsonPaths")
        if isinstance(paths, list) and paths:
            return paths[0]
    return None


# ------------------------------------------------------------------- KQL helpers
def ident(name):
    return "['" + name.replace("\\", "\\\\").replace("'", "\\'") + "']"


def kql_string(s):
    return json.dumps(s, ensure_ascii=False)


def clean(value):
    """Make values safe for a dynamic() literal (no NaN/Infinity)."""
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return None
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [clean(v) for v in value]
    return value


def build_source(columns, events):
    rows = ",\n    ".join(json.dumps(clean(e), ensure_ascii=False, separators=(",", ":")) for e in events)
    fields = []
    for name, ctype in columns:
        fn = CONVERT.get(ctype, "tostring")
        access = f"e[{kql_string(name)}]"
        fields.append(f"    {ident(name)} = {fn}({access})" if fn else f"    {ident(name)} = {access}")
    return ("let source = print _events = dynamic([\n    " + rows + "\n])\n"
            "| mv-expand e = _events\n"
            "| project\n" + ",\n".join(fields) + ";")


def tidy_transform(transform):
    lines = [ln.rstrip() for ln in (transform or "source").replace("\r\n", "\n").split("\n")]
    text = "\n".join(ln for ln in lines if ln.strip())  # blank lines would split the query in the portal
    return text.rstrip().rstrip(";").rstrip()


# --------------------------------------------------------------------- warnings
def check_flow(columns, events, transform, output_stream):
    warnings = []
    declared = {n for n, _ in columns}
    declared_ci = {n.lower(): n for n in declared}
    seen = set().union(*(e.keys() for e in events))
    extra = sorted(seen - declared)
    case_mismatch = [f"{k} (declared as {declared_ci[k.lower()]})" for k in extra if k.lower() in declared_ci]
    ignored = [k for k in extra if k.lower() not in declared_ci]
    if ignored:
        warnings.append("Fields in your events that the stream doesn't declare (the DCR never sees them): "
                        + ", ".join(ignored[:15]) + (" ..." if len(ignored) > 15 else ""))
    if case_mismatch:
        warnings.append("Casing differs from the stream declaration (these may arrive empty): " + ", ".join(case_mismatch))
    missing = [n for n, _ in columns if not any(n in e for e in events)]
    if missing:
        warnings.append("Declared columns missing from every sample event (they'll be empty): " + ", ".join(missing))
    for name, ctype in columns:
        values = [e[name] for e in events if e.get(name) is not None]
        if ctype == "datetime" and any(isinstance(v, (int, float)) and not isinstance(v, bool) for v in values):
            warnings.append(f"'{name}' is declared datetime but holds numbers (epoch?). Declare it long and "
                            "convert in the transform with unixtime_seconds_todatetime()/unixtime_milliseconds_todatetime().")
        if ctype in ("int", "long", "real") and any(isinstance(v, str) and not re.fullmatch(r"\s*-?\d+(\.\d+)?\s*", v) for v in values):
            warnings.append(f"'{name}' is declared {ctype} but some values aren't numbers; they'll become empty.")
    if (output_stream or "").startswith("Custom-") and "timegenerated" not in (transform or "").lower() \
            and "timegenerated" not in declared_ci:
        warnings.append("The transform never sets TimeGenerated and the stream doesn't declare it.")
    if "\n" in (transform or ""):
        warnings.append("transformKql contains line breaks; in the DCR JSON it should be a single line.")
    return warnings


# ------------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description="Preview a DCR transformation against sample events (writes KQL).")
    ap.add_argument("--dcr", required=True, help="file containing the DCR (CCF *_DCR.json, ARM template, CLI export)")
    ap.add_argument("--events", required=True, help="sample events: JSON array, object, or JSON Lines")
    ap.add_argument("--events-path", help="JSONPath to the events inside the file, e.g. '$.items'")
    ap.add_argument("--poller", help="CCF poller file; its response.eventsJsonPaths is used as --events-path")
    ap.add_argument("--table", action="append", default=[], help="table schema file(s); default: search the DCR's folder")
    ap.add_argument("--stream", help="only data flows that read this input stream")
    ap.add_argument("--max-events", type=int, default=50, help="max sample events to embed (default 50)")
    ap.add_argument("-o", "--out", help="write the KQL to this file (default: print it)")
    args = ap.parse_args()

    dcrs = find_dcrs(load_json_lenient(args.dcr))
    if not dcrs:
        sys.exit(f"error: no DCR (streamDeclarations + dataFlows) found in {args.dcr}")

    table_files = args.table or [p for p in glob.glob(os.path.join(os.path.dirname(os.path.abspath(args.dcr)), "*.json"))]
    tables = {}
    for tf in table_files:
        try:
            tables.update(find_tables(load_json_lenient(tf)))
        except SystemExit:
            continue

    path = args.events_path or (poller_events_path(args.poller) if args.poller else None)
    events = to_events(load_json_lenient(args.events), path)
    if len(events) > args.max_events:
        print(f"note: using the first {args.max_events} of {len(events)} events (--max-events)", file=sys.stderr)
        events = events[: args.max_events]

    out = [f"// Generated by dcr_preview.py from {os.path.basename(args.dcr)} and "
           f"{len(events)} sample event(s).",
           "// Each block is one query: put the cursor inside a block and select Run."]
    flows = 0
    for dcr in dcrs:
        streams = {k: [(get_ci(c, "name"), str(get_ci(c, "type", "string")).lower())
                       for c in get_ci(v, "columns", []) if isinstance(c, dict)]
                   for k, v in get_ci(dcr["props"], "streamDeclarations").items()}
        for i, flow in enumerate(get_ci(dcr["props"], "dataFlows"), 1):
            in_streams = [s for s in get_ci(flow, "streams", []) if s in streams]
            if not in_streams or (args.stream and args.stream not in in_streams):
                continue
            flows += 1
            stream, output = in_streams[0], get_ci(flow, "outputStream") or "(default for the stream)"
            columns = streams[stream]
            transform = get_ci(flow, "transformKql") or "source"
            warnings = check_flow(columns, events, transform, output)
            for w in warnings:
                print(f"warning [{dcr['name']} flow {i}]: {w}", file=sys.stderr)

            source = build_source(columns, events)
            body = tidy_transform(transform)
            header = [f"// ---- {dcr['name']} | flow {i}: {stream} -> {output}"]
            header += [f"// warning: {w}" for w in warnings]
            out.append("\n".join(header + ["// Preview: what the table would receive", source, body]))

            # schema check: file-based schema if we have it, else the live table
            table_name = re.sub(r"^(Custom|Microsoft)-", "", output) if output.startswith(("Custom-", "Microsoft-")) else None
            if table_name:
                if table_name.lower() in tables:
                    name, cols = tables[table_name.lower()]
                    rows = ",\n    ".join(f"{kql_string(n)}, {kql_string(SCHEMA_TYPE.get(t, t))}" for n, t in cols)
                    expected = (f"let expected = datatable(ColumnName: string, ExpectedType: string) [\n    {rows}\n];")
                    origin = f"schema from the table file ({name})"
                else:
                    expected = (f"let expected = {ident(table_name)} | getschema | project ColumnName, ExpectedType = ColumnType\n"
                                f"| where ColumnName !in ({', '.join(kql_string(c) for c in SYSTEM_COLUMNS)}) "
                                "and not(ColumnName startswith \"_\");")
                    origin = f"live schema of {table_name} (the table must already exist in the workspace)"
                check = "\n".join([
                    f"// Schema check against the {origin}",
                    expected, source, body,
                    "| getschema",
                    "| project ColumnName, ActualType = ColumnType",
                    "| join kind=fullouter (expected) on ColumnName",
                    "| project Column = iff(isnotempty(ColumnName), ColumnName, ColumnName1), ActualType, ExpectedType,",
                    "    Status = case(isempty(ColumnName1), \"not in table (won't be stored)\",",
                    "                  isempty(ColumnName), \"not set by transform (stays empty)\",",
                    "                  ActualType != ExpectedType, \"type mismatch\",",
                    "                  \"ok\")",
                    "| order by Status asc, Column asc"])
                out.append(check)

    if not flows:
        sys.exit("error: no data flow reads a declared stream" + (f" named {args.stream}" if args.stream else ""))
    text = "\n\n".join(out) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"wrote {args.out} ({flows} data flow(s))", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
