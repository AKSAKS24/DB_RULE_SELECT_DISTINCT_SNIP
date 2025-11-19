from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import re

app = FastAPI(
    title="Rule 727 — Replace DELETE ADJACENT DUPLICATES with SELECT DISTINCT",
    version="2.1"
)

# -----------------------------------------------------------------------------
# Models (aligned with reference: header + findings)
# -----------------------------------------------------------------------------
class Finding(BaseModel):
    prog_name: Optional[str] = None
    incl_name: Optional[str] = None
    types: Optional[str] = None
    blockname: Optional[str] = None
    starting_line: Optional[int] = None
    ending_line: Optional[int] = None
    issues_type: Optional[str] = None   # e.g. "UseSelectDistinct"
    severity: Optional[str] = None      # always "error" per latest requirement
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None       # full line where issue occurs


class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    start_line: Optional[int] = 0
    end_line: Optional[int] = 0
    code: Optional[str] = ""
    findings: Optional[List[Finding]] = None


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def canon_name(raw: Optional[str]) -> Optional[str]:
    return raw.lower() if raw else None


def coalesce_group(m: re.Match, names: List[str]) -> Optional[str]:
    for n in names:
        val = m.groupdict().get(n)
        if val:
            return val
    return None


# ---------------------------------------------------------------------
# HELPER: GET FULL LINE SNIPPET FOR A MATCH (same style as reference)
# ---------------------------------------------------------------------
def get_line_snippet(text: str, start: int, end: int) -> str:
    """
    Given a match span (start, end), return the full line in which
    that match occurs (no extra lines).
    """
    line_start = text.rfind("\n", 0, start)
    if line_start == -1:
        line_start = 0
    else:
        line_start += 1  # right after '\n'

    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)

    return text[line_start:line_end]


# ----------------------------------------------------------------------------- 
# Regexes (robust to @host, inline DATA(), <fs>, (dyn))
# -----------------------------------------------------------------------------
# A single SQL SELECT statement up to the period.
STMT_SELECT_RE = re.compile(r"(?is)\bSELECT\b[^.]*\.", re.DOTALL)

# DISTINCT inside a SELECT
SELECT_DISTINCT_RE = re.compile(r"(?i)\bSELECT\b\s+DISTINCT\b")

# "Target itab token" after INTO/APPENDING TABLE:
# - @lt_tab
# - lt_tab
# - @DATA(lt_tab) / DATA(lt_tab)
# - <lt_tab>
# - (lt_tab)
TARGET_ITAB_TOKEN = r"""
    @?\s*
    (?:
        DATA\s*\(\s*(?P<data>\w+)\s*\)      # @DATA(lt_tab) or DATA(lt_tab)
        |
        <\s*(?P<fs>\w+)\s*>                 # <lt_tab>
        |
        \(\s*(?P<dyn>\w+)\s*\)              # (lt_tab)
        |
        (?P<plain>\w+)                      # lt_tab
    )
"""

# INTO TABLE / INTO CORRESPONDING FIELDS OF TABLE / APPENDING TABLE <target>
INTO_TABLE_ITAB_RE = re.compile(
    rf"""(?is)
        \bINTO\s+
        (?:
            (?:CORRESPONDING\s+FIELDS\s+OF\s+)?TABLE   # INTO [CORRESPONDING FIELDS OF] TABLE
            |
            APPENDING\s+TABLE                          # APPENDING TABLE
        )
        \s+{TARGET_ITAB_TOKEN}
    """,
    re.VERBOSE,
)

# DELETE ADJACENT DUPLICATES FROM <target> [COMPARING ...]. 
STMT_DELETE_DUP_RE = re.compile(
    rf"""(?is)
        \bDELETE\s+ADJACENT\s+DUPLICATES\s+FROM\s+
        {TARGET_ITAB_TOKEN}
        [^.]*\.
    """,
    re.VERBOSE | re.DOTALL,
)


# -----------------------------------------------------------------------------
# Scanner (aligned with reference: Unit + findings, start/end/snippet)
# -----------------------------------------------------------------------------
def scan_unit(unit: Unit) -> Unit:
    src = unit.code or ""
    findings: List[Finding] = []

    base_start = unit.start_line or 0  # block start line in full program

    # 1) Collect all SELECTs that "fill" a table target, record whether DISTINCT is used
    selects: List[Dict[str, Any]] = []
    for m in STMT_SELECT_RE.finditer(src):
        sel_stmt = m.group(0)
        sel_start, sel_end = m.start(), m.end()

        itab_match = INTO_TABLE_ITAB_RE.search(sel_stmt)
        if not itab_match:
            continue

        # resolve target name from any of the allowed shapes
        target_name = coalesce_group(itab_match, ["data", "fs", "dyn", "plain"])
        target_name = canon_name(target_name)
        if not target_name:
            continue

        has_distinct = SELECT_DISTINCT_RE.search(sel_stmt) is not None

        selects.append({
            "itab": target_name,
            "start": sel_start,
            "end": sel_end,
            "has_distinct": has_distinct,
            "stmt": sel_stmt,
        })

    # helper to build a Finding using reference-style start/end/snippet
    def build_finding_for_pair(
        *,
        itab_name: str,
        select_start: int,
        select_end: int,
        delete_start: int,
        delete_end: int,
    ) -> Finding:
        # We anchor the issue to the SELECT (since we want SELECT DISTINCT)
        stmt_start = select_start
        stmt_end = select_end

        # Line within this block (1-based)
        line_in_block = src[:stmt_start].count("\n") + 1

        # Snippet: full line of the SELECT (from src)
        snippet_line = get_line_snippet(src, stmt_start, stmt_end)
        snippet_line_count = snippet_line.count("\n") + 1  # usually 1

        # Absolute line numbers in full program
        starting_line_abs = base_start + line_in_block
        ending_line_abs = base_start + line_in_block + snippet_line_count

        msg = (
            f"SELECT fills '{itab_name}' followed by DELETE ADJACENT DUPLICATES. "
            f"Prefer SELECT DISTINCT."
        )
        suggestion = (
            f"* Replace the SELECT that fills `{itab_name}` with DISTINCT and "
            f"remove the DELETE step.\n\n"
            f"Example rewrite:\n"
            f"  SELECT DISTINCT ...\n"
            f"    INTO TABLE {itab_name}.\n"
            f"  \" DELETE ADJACENT DUPLICATES FROM {itab_name}.  \" <-- remove\n"
        )

        return Finding(
            prog_name=unit.pgm_name,
            incl_name=unit.inc_name,
            types=unit.type,
            blockname=unit.name,
            starting_line=starting_line_abs,
            ending_line=ending_line_abs,
            issues_type="UseSelectDistinct",
            severity="error",  # per your latest instruction
            message=msg,
            suggestion=suggestion,
            snippet=snippet_line.replace("\n", "\\n"),
        )

    # 2) Find DELETE ADJACENT DUPLICATES and pair to most recent prior SELECT on same canonical name
    for d in STMT_DELETE_DUP_RE.finditer(src):
        d_start, d_end = d.start(), d.end()
        d_raw_name = coalesce_group(d, ["data", "fs", "dyn", "plain"])
        d_itab = canon_name(d_raw_name)
        if not d_itab:
            continue

        # Find most recent prior SELECT that filled same canonical name
        prior = None
        for s in selects:
            if s["itab"] == d_itab and s["end"] < d_start:
                if (prior is None) or (s["end"] > prior["end"]):
                    prior = s

        # Only flag when prior exists and was NOT DISTINCT
        if prior and not prior["has_distinct"]:
            finding = build_finding_for_pair(
                itab_name=d_itab,
                select_start=prior["start"],
                select_end=prior["end"],
                delete_start=d_start,
                delete_end=d_end,
            )
            findings.append(finding)

    # Build response Unit: copy header and attach findings
    out_unit = Unit(**unit.model_dump())
    out_unit.findings = findings
    return out_unit


# -----------------------------------------------------------------------------
# Endpoints (return Unit objects with findings[] like reference)
# -----------------------------------------------------------------------------
@app.post("/remediate-array", response_model=List[Unit])
async def scan_rule_array(units: List[Unit]):
    """Scan an array of units; return only those with findings."""
    results: List[Unit] = []
    for u in units:
        res = scan_unit(u)
        if res.findings:
            results.append(res)
    return results


@app.post("/remediate", response_model=Unit)
async def scan_rule_single(unit: Unit):
    """Scan a single unit; always return the unit with any findings attached."""
    return scan_unit(unit)


@app.get("/health")
async def health():
    return {"ok": True, "rule": 727, "version": "2.1"}
