#!/usr/bin/env python3
"""
EU5 Log Analyzer v2
Parses error/debug logs, normalizes parametric messages into pattern groups,
scores by actionability, and exports a prioritized report.
"""

import argparse
import json
import math
import re
import sys
import time
from collections import defaultdict
from datetime import datetime
from enum import Enum
from pathlib import Path


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class State(Enum):
    IDLE = "idle"
    SCRIPT_SYSTEM_ERROR = "script_system_error"
    PERSISTENT_READER = "persistent_reader"


TIMESTAMP_RE = re.compile(r'^\[(\d+:\d+:\d+)\]\[([^\]]+)\]:\s*(.*)')

NORMALIZATION_PATTERNS = [
    # --- engine / data warnings ---
    ("modifier_type.cpp", r"Missing Icon for Modifier : (?P<param>\S+)",
     "Missing Icon for Modifier", "warning"),
    ("building_type.cpp:1851", r"(?P<param>\S+) has no production methods",
     "Building has no production methods", "warning"),
    ("building_type.cpp:848", r"duplicated production method name '(?P<pm>[^']+)' for (?P<param>\S+)",
     "Duplicated production method name", "warning"),
    ("price_database.cpp", r"Missing modifier type for price\.\s*(?P<param>\S+)",
     "Missing modifier type for price", "warning"),
    ("utility.h:242", r"Location rank (?P<param>\S+) has same color as (?P<other>\S+)",
     "Location rank color collision", "warning"),
    ("message_handler.cpp", r"Failed to find message type: (?P<param>\S+)",
     "Failed to find message type", "warning"),
    ("production_methods.cpp", r"The (?P<param>\S+) production_method has",
     "Production method profit out of range", "warning"),
    ("game_concepts.cpp", r"Game concept '(?P<param>[^']+)'.*Missing localization key '(?P<key>[^']+)'",
     "Game concept missing localization", "warning"),
    ("interaction_target.cpp", r"Key (?P<param>\S+) doesn't exist",
     "Interaction target key missing", "warning"),

    # --- script errors ---
    ("jomini_effect.cpp:1166", r"Variable '(?P<param>[^']+)' is used but is never set",
     "Variable used but never set", "error"),
    ("jomini_effect.cpp:1162", r"Variable '(?P<param>[^']+)' is set but is never used",
     "Variable set but never used", "error"),
    ("jomini_eventtarget.cpp", r"Failed to find a valid event target link '(?P<param>[^']+)' at (?P<loc>\S+)",
     "Invalid event target link", "error"),
    ("jomini_trigger.cpp:806", r"(?P<param>\S+): Inconsistent trigger scopes \((?P<scopes>[^)]+)\) at (?P<loc>\S+)",
     "Inconsistent trigger scopes", "error"),
    ("jomini_trigger.cpp:269", r"PostValidate of trigger '(?P<param>[^']+)' returned false at (?P<loc>\S+)",
     "Trigger post-validation failed", "error"),
    ("jomini_script_argument.cpp", r"Compiling source for (?P<effect>\S+) failed for unknown arguments: (?P<param>\S+)",
     "Script compilation failed for unknown arguments", "error"),
    ("jomini_scriptvalue.h:730", r"Cannot read \[(?P<param>[^\]]+)\]",
     "Cannot read script value", "error"),
    ("jomini_scriptvalue.h:438", r"Badly read script value (?P<param>\S+)",
     "Badly read script value", "error"),
    ("jomini_scriptvalue.cpp", r"Value of wrong type in '(?P<loc>[^']+)'",
     "Script value wrong type", "error"),

    # --- persistent reader sub-patterns ---
    ("pdx_persistent_reader.cpp", r'Unknown trigger type: (?P<param>[^,]+)',
     "Unknown trigger type", "error"),
    ("pdx_persistent_reader.cpp", r'Unexpected token: (?P<param>[^,]+)',
     "Unexpected token", "error"),
    ("pdx_persistent_reader.cpp", r'Failed to read key reference',
     "Failed to read key reference", "error"),

    # --- encoding ---
    ("lexer.cpp:501", r"File '(?P<param>[^']+)' should be in utf8-bom encoding",
     "File not in UTF-8 BOM encoding", "info"),
    ("localize.cpp", r"Localization file '(?P<param>[^']+)'.*utf-8-bom",
     "Localization file encoding issue", "info"),
    ("localization_reader.cpp", r"Missing UTF8 BOM in '(?P<param>[^']+)'",
     "Localization file encoding issue", "info"),

    # --- localization fallback ---
    ("localization_util.cpp", r'(?P<param>\S+): "(?P<value>[^"]*)"',
     "Localization fallback (unlocalized key)", "info"),

    # --- textures / VFS ---
    ("virtualfilesystem.cpp", r"VFSOpen Error: (?P<param>\S+) not found",
     "VFS missing texture/file", "info"),
    ("virtualfilesystem.cpp", r"path is over 250 characters long",
     "VFS path too long", "info"),
    ("pdx_gui_glow.cpp:329", r"Only B8G8R8A8_UNORM support so far.*Texture file\s*:\s*(?P<param>\S+)",
     "Texture format not B8G8R8A8_UNORM", "info"),
    ("pdx_gui_glow.cpp:322", r"Failed to load texture data from '(?P<param>[^']+)'",
     "Failed to load texture data", "info"),

    # --- GUI ---
    ("pdx_gui_factory.cpp:2065", r"Template '(?P<param>[^']+)' is already registered",
     "GUI template already registered", "info"),
    ("pdx_gui_localize.cpp", r"Unlocalized text '(?P<param>[^']+)' at (?P<loc>\S+)",
     "GUI unlocalized text", "warning"),
    ("pdx_gui_widget.cpp", r"Property '(?P<param>[^']+)'.*not handled",
     "GUI property not handled", "info"),

    # --- formatting ---
    ("pdx_text_formatter.cpp", r"Unknown formatting tag '(?P<param>[^']+)'",
     "Unknown formatting tag", "info"),

    # --- misc ---
    ("generic_action_ai_list.cpp", r"Action (?P<param>\S+) already in an ai list",
     "Action already in AI list", "warning"),
    ("dlc_reloadable.cpp", r"Mod with path (?P<param>\S+)",
     "Mod metadata issue", "info"),
    ("pdx_mod_metadata.cpp", r"Mod metadata read error.*(?:File: (?P<param>\S+)|Error: (?P<err>.+))",
     "Mod metadata read error", "info"),
    ("portraitaccessories.cpp", r"could not find entity \[(?P<param>[^\]]+)\]",
     "Missing portrait entity", "info"),
    ("tooltip_validation.cpp", r'Button is missing tooltip.*"(?P<param>[^"]+)"',
     "Button missing tooltip", "warning"),
    ("pdxinput_context.cpp", r"Could not push.*context.*ID: (?P<param>\S+)",
     "Input context push failed", "info"),

    # --- bookmark / startup ---
    ("initialize_from_bookmark.cpp", r"Location (?P<loc>\S+) has an invalid building (?P<param>\S+)",
     "Location has invalid building at start", "warning"),
    ("initialize_from_bookmark.cpp", r"Country '(?P<param>[^']+)'.*diplomatic relations over",
     "Country over diplomatic relations limit at start", "info"),
    ("initialize_from_bookmark.cpp", r"Army Based Country '(?P<param>[^']+)'.*can not create regiments",
     "Army-based country cannot create regiments at start", "info"),
    ("initialize_from_bookmark.cpp", r"Country '(?P<param>[^']+)'.*not set as a Core",
     "Locations not set as Core at start", "info"),
    ("building_manager.cpp:59", r"Building '(?P<param>[^']+)' cannot be built in a '(?P<rank>[^']+)'",
     "Building in invalid location rank", "warning"),
    ("building_manager.cpp:125", r"(?P<param>\S+) in .+ is above max level",
     "Building above max level", "warning"),

    # --- jomini_eventmanager ---
    ("jomini_eventmanager.cpp", r"Event (?P<param>\S+) is (?:orphaned|scripted as an orphan)",
     "Orphaned event", "warning"),

    # --- jomini_script_system (multi-line blocks, matched against error_detail) ---
    ("jomini_script_system.cpp", r"Invalid price key!.*Key: '(?P<param>[^']+)'",
     "Script error: Invalid price key", "error"),
    ("jomini_script_system.cpp", r"Failed to fetch variable for '(?P<param>[^']+)'",
     "Script error: Failed to fetch variable", "error"),
    ("jomini_script_system.cpp", r"Failed to fetch map for '(?P<param>[^']+)'",
     "Script error: Failed to fetch map", "error"),
    ("jomini_script_system.cpp", r"Event target link '(?P<param>[^']+)' returned an? (?:invalid object|unset scope)",
     "Script error: Event target returned invalid/unset", "error"),
    ("jomini_script_system.cpp", r"Invalid left side during comparison '(?P<param>[^']+)'",
     "Script error: Invalid comparison left side", "error"),
    ("jomini_script_system.cpp", r"Invalid right side during comparison '(?P<param>[^']+)'",
     "Script error: Invalid comparison right side", "error"),
    ("jomini_script_system.cpp", r"Left side and right side during comparison were of different types.*left was '(?P<param>[^']+)'",
     "Script error: Comparison type mismatch", "error"),
    ("jomini_script_system.cpp", r"Undefined event target '(?P<param>[^']+)'",
     "Script error: Undefined event target", "error"),
    ("jomini_script_system.cpp", r"(?P<param>\S+) (?:effect|trigger) \[.*Wrong scope",
     "Script error: Wrong scope for effect/trigger", "error"),
    ("jomini_script_system.cpp", r"(?P<param>set_variable|change_variable|has_variable) (?:effect|trigger) \[.*doesn't support variables",
     "Script error: Scope doesn't support variables", "error"),
    ("jomini_script_system.cpp", r"trigger_else_if.*(?P<param>no trigger_else)",
     "Script error: trigger_else_if with no trigger_else", "error"),
    ("jomini_script_system.cpp", r"every_(?P<param>\S+) effect \[.*Wrong scope",
     "Script error: Wrong scope for iterator", "error"),
]

_COMPILED_PATTERNS = [
    (src, re.compile(pat), key, sev)
    for src, pat, key, sev in NORMALIZATION_PATTERNS
]

KNOWN_NOISE = {
    "Texture format not B8G8R8A8_UNORM",
    "Unknown formatting tag",
    "Failed to load texture data",
    "VFS path too long",
    "Input context push failed",
}


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def parse_log(log_path, mod_filter=None, timeout=None):
    """Parse EU5 log file with state machine for multi-line messages."""
    messages = []
    state = State.IDLE
    accum = None
    raw_line_count = 0
    timed_out = False
    deadline = time.monotonic() + timeout if timeout else None

    def _emit(msg_dict):
        if mod_filter:
            combined = msg_dict.get("raw_message", "") + " ".join(msg_dict.get("locations", []))
            if mod_filter not in combined:
                return
        messages.append(msg_dict)

    def _flush_accum():
        nonlocal accum, state
        if accum:
            _emit(accum)
            accum = None
        state = State.IDLE

    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            raw_line_count += 1

            if deadline and raw_line_count % 5000 == 0 and time.monotonic() > deadline:
                timed_out = True
                break

            stripped = line.rstrip('\n\r')
            ts_match = TIMESTAMP_RE.match(stripped)

            # --- State: SCRIPT_SYSTEM_ERROR ---
            if state == State.SCRIPT_SYSTEM_ERROR:
                if ts_match:
                    _flush_accum()
                elif stripped.startswith('  Error:'):
                    accum["error_detail"] = stripped.strip()[len("Error:"):].strip()
                    accum["raw_message"] += " | " + stripped.strip()
                    continue
                elif stripped.startswith('  Script location:'):
                    loc = stripped.strip()[len("Script location:"):].strip()
                    accum["locations"].append(loc)
                    continue
                elif stripped.strip() == "":
                    _flush_accum()
                    continue
                else:
                    s = stripped.strip()
                    if s:
                        accum["locations"].append(s)
                    continue

            # --- State: PERSISTENT_READER ---
            if state == State.PERSISTENT_READER:
                if ts_match:
                    _flush_accum()
                else:
                    accum["continuation_count"] += 1
                    if '" in file:' in stripped:
                        file_match = re.search(r'in file:\s*"([^"]*)"', stripped)
                        if file_match and file_match.group(1):
                            accum["locations"].append(file_match.group(1))
                        _flush_accum()
                    continue

            # --- State: IDLE (or fell through from flush) ---
            if not ts_match:
                continue

            timestamp, source, msg = ts_match.group(1), ts_match.group(2), ts_match.group(3).strip()

            if any(skip in msg.lower() for skip in ['loading', 'loaded', 'initializing', 'initialized']):
                continue

            # Detect script system error block
            if 'jomini_script_system' in source and 'Script system error' in msg:
                _flush_accum()
                state = State.SCRIPT_SYSTEM_ERROR
                accum = {
                    "source": source, "timestamp": timestamp,
                    "raw_message": msg, "error_detail": "",
                    "locations": [], "continuation_count": 0,
                }
                continue

            # Detect persistent reader multi-line block
            if 'pdx_persistent_reader' in source and 'Error: "' in msg:
                _flush_accum()
                if '" in file:' in msg:
                    file_match = re.search(r'in file:\s*"([^"]*)"', msg)
                    locs = [file_match.group(1)] if file_match and file_match.group(1) else []
                    _emit({
                        "source": source, "timestamp": timestamp,
                        "raw_message": msg, "error_detail": msg,
                        "locations": locs, "continuation_count": 0,
                    })
                else:
                    state = State.PERSISTENT_READER
                    accum = {
                        "source": source, "timestamp": timestamp,
                        "raw_message": msg, "error_detail": msg,
                        "locations": [], "continuation_count": 0,
                    }
                continue

            # Single-line message
            locs = []
            file_match = re.search(
                r'(?:file|in|at)\s+["\']?([^"\':\s]+\.(?:txt|gui|gfx|yml))["\']?(?::(\d+))?',
                msg, re.IGNORECASE
            )
            if file_match:
                loc = file_match.group(1)
                if file_match.group(2):
                    loc += ":" + file_match.group(2)
                locs.append(loc)

            _emit({
                "source": source, "timestamp": timestamp,
                "raw_message": msg, "error_detail": "",
                "locations": locs, "continuation_count": 0,
            })

    _flush_accum()
    return messages, raw_line_count, timed_out


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def normalize_messages(messages):
    """Group parsed messages into normalized pattern buckets."""
    groups = defaultdict(lambda: {
        "pattern_key": None, "severity": "info", "source": "",
        "instance_count": 0, "params": [], "locations": [],
        "examples": [],
    })

    for msg in messages:
        source = msg["source"]
        text = msg.get("error_detail") or msg["raw_message"]
        matched = False

        for src_substr, pat_re, pat_key, severity in _COMPILED_PATTERNS:
            if src_substr not in source:
                continue
            m = pat_re.search(text)
            if m:
                g = groups[pat_key]
                g["pattern_key"] = pat_key
                g["severity"] = severity
                g["source"] = source
                g["instance_count"] += 1
                param = m.groupdict().get("param")
                if param and param not in g["params"]:
                    g["params"].append(param)
                for loc in msg["locations"]:
                    if loc and loc not in g["locations"]:
                        g["locations"].append(loc)
                if len(g["examples"]) < 3:
                    g["examples"].append(msg["raw_message"])
                matched = True
                break

        if not matched:
            key = f"_uncategorized:{source}:{text[:120]}"
            g = groups[key]
            g["pattern_key"] = key
            g["severity"] = _guess_severity(text)
            g["source"] = source
            g["instance_count"] += 1
            if len(g["examples"]) < 3:
                g["examples"].append(msg["raw_message"])
            for loc in msg["locations"]:
                if loc and loc not in g["locations"]:
                    g["locations"].append(loc)

    return dict(groups)


def _guess_severity(text):
    t = text.lower()
    if "error" in t or "failed" in t or "invalid" in t:
        return "error"
    if "warning" in t or "missing" in t:
        return "warning"
    return "info"


# ---------------------------------------------------------------------------
# Priority scoring
# ---------------------------------------------------------------------------

def compute_priority(group):
    score = 0.0
    sev = group["severity"]
    if sev == "error":
        score += 100
    elif sev == "warning":
        score += 50
    else:
        score += 10

    score += min(math.log2(group["instance_count"] + 1) * 10, 50)

    if group["instance_count"] <= 3:
        score += 40

    has_sul = any("sul_" in str(p) for p in group["params"]) or \
              any("sul_" in str(l) for l in group["locations"])
    if has_sul:
        score += 30

    if group["pattern_key"] in KNOWN_NOISE:
        score -= 200

    return round(score, 1)


# ---------------------------------------------------------------------------
# Report output
# ---------------------------------------------------------------------------

SEV_BADGE = {"error": "ERROR", "warning": "WARN", "info": "INFO"}


def export_report(groups, output_path, log_path, raw_line_count,
                  mod_filter=None, verbose=False, no_suppress=False,
                  timed_out=False):
    scored = []
    for key, g in groups.items():
        g["priority"] = compute_priority(g)
        scored.append(g)

    actionable = []
    suppressed = []
    for g in scored:
        if not no_suppress and g["pattern_key"] in KNOWN_NOISE:
            suppressed.append(g)
        else:
            actionable.append(g)

    actionable.sort(key=lambda g: g["priority"], reverse=True)
    suppressed.sort(key=lambda g: g["instance_count"], reverse=True)

    total_messages = sum(g["instance_count"] for g in scored)
    err_count = sum(1 for g in scored if g["severity"] == "error")
    warn_count = sum(1 for g in scored if g["severity"] == "warning")
    info_count = sum(1 for g in scored if g["severity"] == "info")
    suppressed_msg_count = sum(g["instance_count"] for g in suppressed)

    log_name = Path(log_path).name

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(f"# EU5 Error Analysis: {log_name}\n\n")
        if timed_out:
            f.write("> **Warning:** Parse timed out — results are partial.\n\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"**Source:** `{log_path}`\n\n")
        if mod_filter:
            f.write(f"**Filter:** `{mod_filter}`\n\n")

        f.write("## Summary\n\n")
        f.write("| Metric | Value |\n")
        f.write("|--------|-------|\n")
        f.write(f"| Raw log lines | {raw_line_count:,} |\n")
        f.write(f"| Logical messages | {total_messages:,} |\n")
        f.write(f"| Pattern groups | {len(scored)} |\n")
        f.write(f"| Error groups | {err_count} |\n")
        f.write(f"| Warning groups | {warn_count} |\n")
        f.write(f"| Info groups | {info_count} |\n")
        f.write(f"| Suppressed noise messages | {suppressed_msg_count:,} |\n")
        f.write("\n---\n\n")

        f.write("## Actionable Errors\n\n")
        for i, g in enumerate(actionable, 1):
            _write_group(f, i, g, verbose)

        if suppressed:
            f.write("## Suppressed Noise\n\n")
            f.write("Known engine-level messages collapsed here. Use `--no-suppress` to include above.\n\n")
            f.write("| Pattern | Count |\n")
            f.write("|---------|-------|\n")
            for g in suppressed:
                f.write(f"| {g['pattern_key']} | {g['instance_count']:,} |\n")
            f.write(f"\n**Total suppressed:** {suppressed_msg_count:,}\n\n")
            f.write("---\n\n")

        f.write("## Full Pattern Index\n\n")
        all_sorted = sorted(scored, key=lambda g: g["priority"], reverse=True)
        f.write("| # | Sev | Count | Priority | Pattern | Source |\n")
        f.write("|---|-----|-------|----------|---------|--------|\n")
        for i, g in enumerate(all_sorted, 1):
            badge = SEV_BADGE.get(g["severity"], "INFO")
            pk = g["pattern_key"]
            if pk.startswith("_uncategorized:"):
                parts = pk.split(":", 2)
                pk = f"~ {parts[2][:60]}"
            f.write(f"| {i} | {badge} | {g['instance_count']:,} | {g['priority']} | {pk} | {g['source']} |\n")

    return actionable, suppressed


def _write_group(f, index, g, verbose):
    badge = SEV_BADGE.get(g["severity"], "INFO")
    pk = g["pattern_key"]
    display_key = pk
    if pk.startswith("_uncategorized:"):
        parts = pk.split(":", 2)
        display_key = f"(uncategorized) {parts[1]}: {parts[2]}"

    f.write(f"### {index}. [{badge}] {display_key} ({g['instance_count']:,} instances)\n\n")
    f.write(f"**Source:** `{g['source']}`  \n")
    f.write(f"**Priority:** {g['priority']}\n\n")

    if g["params"]:
        limit = None if verbose else 10
        shown = g["params"][:limit]
        f.write("**Values:**\n")
        for p in shown:
            f.write(f"- `{p}`\n")
        remaining = len(g["params"]) - len(shown)
        if remaining > 0:
            f.write(f"- ... ({remaining} more, use --verbose)\n")
        f.write("\n")

    if g["locations"]:
        limit = None if verbose else 10
        shown = g["locations"][:limit]
        f.write("**Locations:**\n")
        for loc in shown:
            f.write(f"- `{loc}`\n")
        remaining = len(g["locations"]) - len(shown)
        if remaining > 0:
            f.write(f"- ... ({remaining} more)\n")
        f.write("\n")

    if g["examples"]:
        f.write(f"**Example:** `{g['examples'][0][:200]}`\n\n")

    f.write("---\n\n")


def print_plaintext(groups, log_path, raw_line_count, mod_filter=None,
                    timed_out=False, no_suppress=False):
    """Print plaintext summary to stdout for piping to Claude."""
    scored = []
    for key, g in groups.items():
        g["priority"] = compute_priority(g)
        scored.append(g)

    actionable = []
    suppressed_count = 0
    for g in scored:
        if not no_suppress and g["pattern_key"] in KNOWN_NOISE:
            suppressed_count += g["instance_count"]
        else:
            actionable.append(g)

    actionable.sort(key=lambda g: g["priority"], reverse=True)
    total_messages = sum(g["instance_count"] for g in scored)

    print("EU5 ERROR LOG ANALYSIS")
    if timed_out:
        print("NOTE: Parse timed out — results are partial")
    print(f"Source: {log_path}")
    if mod_filter:
        print(f"Filter: {mod_filter}")
    print(f"Total: {total_messages:,} messages → {len(scored)} groups ({suppressed_count:,} suppressed)")
    print()

    for i, g in enumerate(actionable, 1):
        badge = SEV_BADGE.get(g["severity"], "INFO")
        pk = g["pattern_key"]
        if pk.startswith("_uncategorized:"):
            parts = pk.split(":", 2)
            pk = f"~ {parts[2][:80]}"
        print(f"  {i}. [{badge}] {pk} ({g['instance_count']:,}x, priority {g['priority']})")

        if g["params"]:
            shown = g["params"][:5]
            param_str = ", ".join(shown)
            if len(g["params"]) > 5:
                param_str += f" ... (+{len(g['params']) - 5} more)"
            print(f"     values: {param_str}")

        if g["locations"]:
            shown = g["locations"][:3]
            loc_str = ", ".join(shown)
            if len(g["locations"]) > 3:
                loc_str += f" ... (+{len(g['locations']) - 3} more)"
            print(f"     at: {loc_str}")

    print()


def export_json(groups, output_path, log_path, raw_line_count,
                mod_filter=None, timed_out=False):
    scored = []
    for key, g in groups.items():
        g["priority"] = compute_priority(g)
        scored.append(g)
    scored.sort(key=lambda g: g["priority"], reverse=True)

    data = {
        "source": log_path,
        "generated": datetime.now().isoformat(),
        "filter": mod_filter,
        "raw_line_count": raw_line_count,
        "total_messages": sum(g["instance_count"] for g in scored),
        "timed_out": timed_out,
        "groups": scored,
    }
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str)


# ---------------------------------------------------------------------------
# Log discovery
# ---------------------------------------------------------------------------

def list_logs(logs_dir):
    """List available .log files in the EU5 logs directory."""
    if not logs_dir.is_dir():
        print(f"Logs directory not found: {logs_dir}", file=sys.stderr)
        sys.exit(1)

    logs = sorted(f for f in logs_dir.iterdir() if f.suffix == ".log")
    if not logs:
        print(f"No .log files found in: {logs_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Available logs in {logs_dir}:\n")
    for log in logs:
        size = log.stat().st_size
        if size < 1024:
            size_str = f"{size} B"
        elif size < 1024 * 1024:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size / (1024 * 1024):.1f} MB"
        print(f"  {log.name:<40} {size_str:>10}")

    print(f"\nUsage: eu5-logs <log_name>")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    logs_dir = Path("/mnt/c/Users/mjaklitsch/Documents/Paradox Interactive/Europa Universalis V/logs")

    parser = argparse.ArgumentParser(description="EU5 Log Analyzer v2")
    parser.add_argument("log", nargs="?", default=None,
                        help="Log file name or path (omit to list available logs)")
    parser.add_argument("-o", "--output", help="Path to output report")
    parser.add_argument("-f", "--filter",
                        help="Only include messages matching this string")
    parser.add_argument("-p", "--plain", action="store_true",
                        help="Print plaintext summary to stdout (for piping to Claude)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show full parameter lists (no truncation)")
    parser.add_argument("-t", "--timeout", type=float, default=None,
                        help="Timeout in seconds (returns partial results if exceeded)")
    parser.add_argument("--no-suppress", action="store_true",
                        help="Disable noise suppression")
    parser.add_argument("--json", action="store_true",
                        help="Output JSON instead of markdown")
    args = parser.parse_args()

    if args.log is None:
        list_logs(logs_dir)
        sys.exit(0)

    # Resolve log path: accept bare name or full path
    log_arg = Path(args.log)
    if log_arg.is_file():
        log_path = str(log_arg)
    else:
        candidate = logs_dir / args.log
        if not candidate.suffix:
            candidate = candidate.with_suffix(".log")
        if candidate.is_file():
            log_path = str(candidate)
        else:
            print(f"Log file not found: {args.log}", file=sys.stderr)
            print("Run 'eu5-logs' with no arguments to list available logs.", file=sys.stderr)
            sys.exit(1)

    messages, raw_line_count, timed_out = parse_log(log_path, args.filter,
                                                     timeout=args.timeout)

    if timed_out:
        print(f"WARNING: Timed out after {args.timeout}s — results are partial\n",
              file=sys.stderr)

    groups = normalize_messages(messages)

    if args.plain:
        print_plaintext(groups, log_path, raw_line_count, args.filter,
                        timed_out=timed_out, no_suppress=args.no_suppress)
    elif args.json:
        ext = ".json"
        if args.output:
            output_path = args.output
        else:
            log_name = Path(log_path).stem
            output_path = str(Path(log_path).parent / f"{log_name}_analysis{ext}")
        export_json(groups, output_path, log_path, raw_line_count,
                    args.filter, timed_out=timed_out)
        total = sum(g["instance_count"] for g in groups.values())
        print(f"Parsed {raw_line_count:,} lines → {total:,} messages → {len(groups)} groups")
        print(f"Report saved to: {output_path}")
    else:
        if args.output:
            output_path = args.output
        else:
            log_name = Path(log_path).stem
            output_path = str(Path(log_path).parent / f"{log_name}_analysis.md")
        export_report(groups, output_path, log_path, raw_line_count,
                      mod_filter=args.filter, verbose=args.verbose,
                      no_suppress=args.no_suppress, timed_out=timed_out)
        total = sum(g["instance_count"] for g in groups.values())
        noise = sum(g["instance_count"] for g in groups.values()
                    if g["pattern_key"] in KNOWN_NOISE)
        print(f"Parsed {raw_line_count:,} lines → {total:,} messages → {len(groups)} groups")
        print(f"  Suppressed noise: {noise:,} messages")
        print(f"Report saved to: {output_path}")


if __name__ == "__main__":
    main()
