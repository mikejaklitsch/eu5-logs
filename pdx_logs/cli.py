#!/usr/bin/env python3
"""
pdx-logs: Paradox (EU5) log analyzer.

Stitches rotated logs into one chronological stream, scopes to the current
game session, normalizes parametric messages into pattern groups, scores by
actionability, and exports a prioritized report.

Commands:
    pdx-logs                    list available logs
    pdx-logs <log> [...]        analyze one log (rotation set stitched in)
    pdx-logs sweep [...]        analyze all relevant log types in one pass
    pdx-logs grep <PREFIX> [..] pull mod script-log lines (debug_log/error_log)
                                across debug.log + the error rotation set

Exit codes: 0 = clean, 1 = error-severity findings present, 2 = tool failure.
"""

import argparse
import json
import math
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta
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
LOCATION_RE = re.compile(
    r'(?:file|in|at)\s+["\']?([^"\':\s]+\.(?:txt|gui|gfx|yml))["\']?(?::(\d+))?',
    re.IGNORECASE
)

# Source keys may carry an engine line number for documentation, but matching
# is on the file name only: engine patches shift line numbers and would
# silently degrade matches to uncategorized.
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
    (src.split(":")[0], re.compile(pat), key, sev)
    for src, pat, key, sev in NORMALIZATION_PATTERNS
]

KNOWN_NOISE = {
    "Texture format not B8G8R8A8_UNORM",
    "Unknown formatting tag",
    "Failed to load texture data",
    "VFS path too long",
    "Input context push failed",
}

SWEEP_LOGS = ["error", "game", "debug", "gui", "database_conflicts"]

# Max non-timestamped continuation lines attached to an unknown-format message
MAX_CONTINUATION = 8


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_LOGS_DIR = Path(
    "/mnt/c/Users/Mjaklitsch/Documents/Paradox Interactive/Europa Universalis V/logs")
CONFIG_PATH = Path.home() / ".config" / "pdx-logs.json"
DEFAULT_PREFIXES = ["sul_", "epbm_"]


def load_config():
    cfg = {"prefixes": list(DEFAULT_PREFIXES), "logs_dir": None}
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data.get("prefixes"), list):
            cfg["prefixes"] = [str(p) for p in data["prefixes"]]
        if data.get("logs_dir"):
            cfg["logs_dir"] = str(data["logs_dir"])
    except (OSError, ValueError):
        pass
    return cfg


def resolve_logs_dir(cfg):
    env = os.environ.get("PDX_LOG_DIR")
    if env:
        return Path(env)
    if cfg.get("logs_dir"):
        return Path(cfg["logs_dir"])
    return DEFAULT_LOGS_DIR


# ---------------------------------------------------------------------------
# Log set resolution & session detection
# ---------------------------------------------------------------------------

def resolve_log_set(logs_dir, name, rotation=True):
    """Resolve a log name to its rotation set, oldest first.

    Accepts a bare name ('error'), a file name ('error.log'), or a path.
    Returns (label, [paths oldest..newest]).
    """
    arg = Path(name)
    if arg.is_file() and str(arg.parent) != ".":
        logs_dir = arg.parent
    stem = arg.name
    if stem.endswith(".log"):
        stem = stem[:-4]
    stem = re.sub(r"\.\d+$", "", stem)

    base = logs_dir / f"{stem}.log"
    paths = []
    if rotation:
        rotated = []
        for p in logs_dir.glob(f"{stem}.*.log"):
            m = re.fullmatch(rf"{re.escape(stem)}\.(\d+)\.log", p.name)
            if m:
                rotated.append((int(m.group(1)), p))
        # Highest N is oldest
        paths.extend(p for _, p in sorted(rotated, reverse=True))
    if base.is_file():
        paths.append(base)
    return stem, paths


def _ts_to_secs(ts):
    h, m, s = ts.split(":")
    return int(h) * 3600 + int(m) * 60 + int(s)


def detect_session_start(logs_dir):
    """Detect the most recent game launch.

    Returns (secs_of_day, launch_epoch, source_desc) or None. Anchors on
    setup.log's 'Exe Git Version' line (written once per launch); falls back
    to debug.log's first line. Launch date comes from the anchor file's mtime.
    """
    for fname, marker in (("setup.log", "Exe Git Version"), ("debug.log", None)):
        p = logs_dir / fname
        try:
            if not p.is_file() or p.stat().st_size == 0:
                continue
        except OSError:
            continue
        anchor_ts = None
        try:
            with open(p, encoding="utf-8-sig", errors="ignore") as f:
                for line in f:
                    m = TIMESTAMP_RE.match(line)
                    if not m:
                        continue
                    if marker is None:
                        anchor_ts = m.group(1)
                        break
                    if marker in line:
                        anchor_ts = m.group(1)  # last occurrence wins
        except OSError:
            continue
        if anchor_ts is None:
            continue
        secs = _ts_to_secs(anchor_ts)
        mtime = p.stat().st_mtime
        mt_date = datetime.fromtimestamp(mtime).date()
        launch = datetime.combine(mt_date, datetime.min.time()) + timedelta(seconds=secs)
        # If the constructed launch postdates the file's own mtime, the
        # session crossed midnight and the launch was the previous day.
        if launch.timestamp() > mtime + 60:
            launch -= timedelta(days=1)
        return secs, launch.timestamp(), f"{fname} {anchor_ts}"
    return None


def split_session_files(paths, launch_epoch):
    """Split a rotation set into (pre-session files, current-session files)
    by mtime: a file last written before the launch cannot contain current
    data."""
    if launch_epoch is None:
        return [], list(paths)
    pre, cur = [], []
    for p in paths:
        try:
            if p.stat().st_mtime < launch_epoch - 5:
                pre.append(p)
            else:
                cur.append(p)
        except OSError:
            cur.append(p)
    return pre, cur


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def parse_files(paths, mod_filter=None, timeout=None, session_secs=None):
    """Parse a chronological sequence of log files as one stream.

    session_secs: seconds-of-day of the current launch; messages before the
    first timestamp at/after it are skipped (files entirely from previous
    sessions should already be excluded via split_session_files).
    """
    messages = []
    state = State.IDLE
    accum = None
    pending = None
    pending_continuations = 0
    raw_line_count = 0
    timed_out = False
    gate_open = session_secs is None
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

    def _flush_pending():
        nonlocal pending, pending_continuations
        if pending:
            _emit(pending)
            pending = None
        pending_continuations = 0

    for path in paths:
        if timed_out:
            break
        try:
            f = open(path, encoding="utf-8-sig", errors="ignore")
        except OSError as e:
            print(f"WARNING: cannot read {path}: {e}", file=sys.stderr)
            continue
        with f:
            for line in f:
                raw_line_count += 1

                if deadline and raw_line_count % 5000 == 0 and time.monotonic() > deadline:
                    timed_out = True
                    break

                stripped = line.rstrip("\n\r")
                ts_match = TIMESTAMP_RE.match(stripped)

                # Session gate: skip everything until the launch timestamp
                # appears. Once open it stays open (midnight-safe).
                if not gate_open:
                    if ts_match and _ts_to_secs(ts_match.group(1)) >= session_secs:
                        gate_open = True
                    else:
                        continue

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

                # --- State: IDLE ---
                if not ts_match:
                    # Unknown multi-line format: attach to the previous
                    # message instead of dropping the line.
                    s = stripped.strip()
                    if pending and s and pending_continuations < MAX_CONTINUATION:
                        pending["raw_message"] += " | " + s
                        pending_continuations += 1
                        loc_match = LOCATION_RE.search(s)
                        if loc_match:
                            loc = loc_match.group(1)
                            if loc_match.group(2):
                                loc += ":" + loc_match.group(2)
                            pending["locations"].append(loc)
                    continue

                timestamp, source, msg = ts_match.group(1), ts_match.group(2), ts_match.group(3).strip()

                # Detect script system error block
                if 'jomini_script_system' in source and 'Script system error' in msg:
                    _flush_pending()
                    _flush_accum()
                    state = State.SCRIPT_SYSTEM_ERROR
                    accum = {
                        "source": source, "timestamp": timestamp,
                        "raw_message": msg, "error_detail": "",
                        "locations": [], "continuation_count": 0,
                        "file": path.name,
                    }
                    continue

                # Detect persistent reader multi-line block
                if 'pdx_persistent_reader' in source and 'Error: "' in msg:
                    _flush_pending()
                    _flush_accum()
                    if '" in file:' in msg:
                        file_match = re.search(r'in file:\s*"([^"]*)"', msg)
                        locs = [file_match.group(1)] if file_match and file_match.group(1) else []
                        _emit({
                            "source": source, "timestamp": timestamp,
                            "raw_message": msg, "error_detail": msg,
                            "locations": locs, "continuation_count": 0,
                            "file": path.name,
                        })
                    else:
                        state = State.PERSISTENT_READER
                        accum = {
                            "source": source, "timestamp": timestamp,
                            "raw_message": msg, "error_detail": msg,
                            "locations": [], "continuation_count": 0,
                            "file": path.name,
                        }
                    continue

                # Single-line message: buffer so unknown continuation lines
                # can still attach to it.
                _flush_pending()
                locs = []
                file_match = LOCATION_RE.search(msg)
                if file_match:
                    loc = file_match.group(1)
                    if file_match.group(2):
                        loc += ":" + file_match.group(2)
                    locs.append(loc)

                pending = {
                    "source": source, "timestamp": timestamp,
                    "raw_message": msg, "error_detail": "",
                    "locations": locs, "continuation_count": 0,
                    "file": path.name,
                }

    _flush_pending()
    _flush_accum()
    return messages, raw_line_count, timed_out


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

_MASK_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")
_MASK_BRACKET = re.compile(r"\[[^\]]*\]")
_MASK_NUM = re.compile(r"\d+(?:\.\d+)?")


def _mask_text(text):
    """Generalize a message so near-identical variants share one group key."""
    t = _MASK_QUOTED.sub("'…'", text)
    t = _MASK_BRACKET.sub("[…]", t)
    t = _MASK_NUM.sub("#", t)
    return t


def normalize_messages(messages):
    """Group parsed messages into normalized pattern buckets."""
    groups = defaultdict(lambda: {
        "pattern_key": None, "severity": "info", "source": "",
        "instance_count": 0, "params": [], "locations": [],
        "examples": [],
    })

    for msg in messages:
        source = msg["source"]
        source_file = source.split(":")[0]
        text = msg.get("error_detail") or msg["raw_message"]
        matched = False

        for src_file, pat_re, pat_key, severity in _COMPILED_PATTERNS:
            if src_file not in source:
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
            key = f"_uncategorized:{source_file}:{_mask_text(text)[:120]}"
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

def compute_priority(group, prefixes):
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

    haystacks = [str(p) for p in group["params"]] + [str(l) for l in group["locations"]]
    if any(pfx in h for pfx in prefixes for h in haystacks):
        score += 30

    if group["pattern_key"] in KNOWN_NOISE:
        score -= 200

    return round(score, 1)


def score_and_split(groups, prefixes, no_suppress=False):
    scored = []
    for g in groups.values():
        g["priority"] = compute_priority(g, prefixes)
        scored.append(g)
    actionable, suppressed = [], []
    for g in scored:
        if not no_suppress and g["pattern_key"] in KNOWN_NOISE:
            suppressed.append(g)
        else:
            actionable.append(g)
    actionable.sort(key=lambda g: g["priority"], reverse=True)
    suppressed.sort(key=lambda g: g["instance_count"], reverse=True)
    return scored, actionable, suppressed


def has_error_findings(actionable):
    return any(g["severity"] == "error" for g in actionable)


# ---------------------------------------------------------------------------
# Report output
# ---------------------------------------------------------------------------

SEV_BADGE = {"error": "ERROR", "warning": "WARN", "info": "INFO"}


def _display_key(pk, width=80):
    if pk.startswith("_uncategorized:"):
        parts = pk.split(":", 2)
        return f"~ {parts[1]}: {parts[2][:width]}"
    return pk


def export_report(f, meta, scored, actionable, suppressed, verbose=False):
    total_messages = sum(g["instance_count"] for g in scored)
    suppressed_msg_count = sum(g["instance_count"] for g in suppressed)
    err_count = sum(1 for g in scored if g["severity"] == "error")
    warn_count = sum(1 for g in scored if g["severity"] == "warning")
    info_count = sum(1 for g in scored if g["severity"] == "info")

    f.write(f"# PDX Log Analysis: {meta['label']}\n\n")
    if meta.get("timed_out"):
        f.write("> **Warning:** Parse timed out; results are partial.\n\n")
    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    f.write(f"**Files:** {', '.join(p.name for p in meta['files']) or '(none)'}\n\n")
    if meta.get("skipped"):
        f.write(f"**Skipped (previous session):** {', '.join(p.name for p in meta['skipped'])}\n\n")
    if meta.get("session_desc"):
        f.write(f"**Session:** {meta['session_desc']}\n\n")
    if meta.get("mod_filter"):
        f.write(f"**Filter:** `{meta['mod_filter']}`\n\n")

    f.write("## Summary\n\n")
    f.write("| Metric | Value |\n|--------|-------|\n")
    f.write(f"| Raw log lines | {meta['raw_line_count']:,} |\n")
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
        f.write("| Pattern | Count |\n|---------|-------|\n")
        for g in suppressed:
            f.write(f"| {g['pattern_key']} | {g['instance_count']:,} |\n")
        f.write(f"\n**Total suppressed:** {suppressed_msg_count:,}\n\n---\n\n")

    f.write("## Full Pattern Index\n\n")
    all_sorted = sorted(scored, key=lambda g: g["priority"], reverse=True)
    f.write("| # | Sev | Count | Priority | Pattern | Source |\n")
    f.write("|---|-----|-------|----------|---------|--------|\n")
    for i, g in enumerate(all_sorted, 1):
        badge = SEV_BADGE.get(g["severity"], "INFO")
        pk = _display_key(g["pattern_key"], 60)
        f.write(f"| {i} | {badge} | {g['instance_count']:,} | {g['priority']} | {pk} | {g['source']} |\n")


def _write_group(f, index, g, verbose):
    badge = SEV_BADGE.get(g["severity"], "INFO")
    f.write(f"### {index}. [{badge}] {_display_key(g['pattern_key'])} ({g['instance_count']:,} instances)\n\n")
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


def print_plaintext(meta, scored, actionable, suppressed):
    total_messages = sum(g["instance_count"] for g in scored)
    suppressed_count = sum(g["instance_count"] for g in suppressed)

    print(f"PDX LOG ANALYSIS: {meta['label']}")
    if meta.get("timed_out"):
        print("NOTE: Parse timed out; results are partial")
    print(f"Files: {', '.join(p.name for p in meta['files']) or '(none)'}")
    if meta.get("skipped"):
        print(f"Skipped (previous session): {', '.join(p.name for p in meta['skipped'])}")
    if meta.get("session_desc"):
        print(f"Session: {meta['session_desc']}")
    if meta.get("mod_filter"):
        print(f"Filter: {meta['mod_filter']}")
    print(f"Total: {total_messages:,} messages -> {len(scored)} groups ({suppressed_count:,} suppressed)")
    print()

    for i, g in enumerate(actionable, 1):
        badge = SEV_BADGE.get(g["severity"], "INFO")
        print(f"  {i}. [{badge}] {_display_key(g['pattern_key'])} ({g['instance_count']:,}x, priority {g['priority']})")

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


def export_json_report(output_path, meta, scored):
    scored = sorted(scored, key=lambda g: g["priority"], reverse=True)
    data = {
        "label": meta["label"],
        "files": [str(p) for p in meta["files"]],
        "skipped_previous_session": [str(p) for p in meta.get("skipped", [])],
        "session": meta.get("session_desc"),
        "generated": datetime.now().isoformat(),
        "filter": meta.get("mod_filter"),
        "raw_line_count": meta["raw_line_count"],
        "total_messages": sum(g["instance_count"] for g in scored),
        "timed_out": meta.get("timed_out", False),
        "groups": scored,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _session_scope(logs_dir, paths, all_sessions):
    """Apply session scoping. Returns (files, skipped, session_secs, desc)."""
    if all_sessions:
        return list(paths), [], None, "all sessions"
    session = detect_session_start(logs_dir)
    if session is None:
        return list(paths), [], None, "unknown (no launch anchor found; showing everything)"
    secs, launch_epoch, src = session
    pre, cur = split_session_files(paths, launch_epoch)
    return cur, pre, secs, f"current (launched {src})"


def _analyze_one(logs_dir, name, args):
    """Shared analyze pipeline. Returns (meta, scored, actionable, suppressed)
    or None if the log does not exist."""
    label, paths = resolve_log_set(logs_dir, name, rotation=not args.no_rotation)
    if not paths:
        return None
    files, skipped, session_secs, session_desc = _session_scope(
        logs_dir, paths, args.all_sessions)
    messages, raw_line_count, timed_out = parse_files(
        files, args.filter, timeout=args.timeout, session_secs=session_secs)
    groups = normalize_messages(messages)
    scored, actionable, suppressed = score_and_split(
        groups, args.prefixes, no_suppress=args.no_suppress)
    meta = {
        "label": label, "files": files, "skipped": skipped,
        "session_desc": session_desc, "raw_line_count": raw_line_count,
        "timed_out": timed_out, "mod_filter": args.filter,
    }
    return meta, scored, actionable, suppressed


def _add_common_args(parser):
    parser.add_argument("-f", "--filter",
                        help="Only include messages matching this string")
    parser.add_argument("-t", "--timeout", type=float, default=None,
                        help="Timeout in seconds (partial results if exceeded)")
    parser.add_argument("--all-sessions", action="store_true",
                        help="Include previous sessions (default: current session only)")
    parser.add_argument("--no-suppress", action="store_true",
                        help="Disable noise suppression")
    parser.add_argument("--prefix",
                        help="Comma-separated mod prefixes for priority boost "
                             "(default from ~/.config/pdx-logs.json or sul_,epbm_)")


def _resolve_prefixes(args, cfg):
    if args.prefix:
        return [p.strip() for p in args.prefix.split(",") if p.strip()]
    return cfg["prefixes"]


def cmd_analyze(argv, cfg):
    parser = argparse.ArgumentParser(
        prog="pdx-logs",
        description="Paradox (EU5) log analyzer. Stitches rotated logs, scopes "
                    "to the current session, groups errors by pattern.",
        epilog="Exit codes: 0 clean, 1 error-severity findings, 2 tool failure. "
               "Subcommands: sweep (all log types), grep (mod script-log lines), list.")
    parser.add_argument("log", nargs="?", default=None,
                        help="Log name (e.g. 'error'; rotation set auto-included) "
                             "or path. Omit to list available logs.")
    parser.add_argument("-o", "--output", help="Path to output report")
    parser.add_argument("-p", "--plain", action="store_true",
                        help="Plaintext summary to stdout (for LLM consumption)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Full parameter lists, no truncation")
    parser.add_argument("--json", action="store_true",
                        help="Output JSON instead of markdown")
    parser.add_argument("--no-rotation", action="store_true",
                        help="Analyze only the named file, not its rotation set")
    _add_common_args(parser)
    args = parser.parse_args(argv)
    args.prefixes = _resolve_prefixes(args, cfg)

    logs_dir = resolve_logs_dir(cfg)
    if args.log is None:
        return cmd_list(cfg)

    result = _analyze_one(logs_dir, args.log, args)
    if result is None:
        print(f"Log file not found: {args.log}", file=sys.stderr)
        print("Run 'pdx-logs' with no arguments to list available logs.", file=sys.stderr)
        return 2
    meta, scored, actionable, suppressed = result

    if meta["timed_out"]:
        print(f"WARNING: Timed out after {args.timeout}s; results are partial\n",
              file=sys.stderr)

    if args.plain:
        print_plaintext(meta, scored, actionable, suppressed)
    elif args.json:
        output_path = args.output or str(Path.cwd() / f"{meta['label']}_analysis.json")
        export_json_report(output_path, meta, scored)
        total = sum(g["instance_count"] for g in scored)
        print(f"Parsed {meta['raw_line_count']:,} lines -> {total:,} messages -> {len(scored)} groups")
        print(f"Report saved to: {output_path}")
    else:
        output_path = args.output or str(Path.cwd() / f"{meta['label']}_analysis.md")
        with open(output_path, "w", encoding="utf-8") as f:
            export_report(f, meta, scored, actionable, suppressed, verbose=args.verbose)
        total = sum(g["instance_count"] for g in scored)
        noise = sum(g["instance_count"] for g in suppressed)
        print(f"Parsed {meta['raw_line_count']:,} lines -> {total:,} messages -> {len(scored)} groups")
        print(f"  Suppressed noise: {noise:,} messages")
        print(f"Report saved to: {output_path}")

    return 1 if has_error_findings(actionable) else 0


def cmd_sweep(argv, cfg):
    parser = argparse.ArgumentParser(
        prog="pdx-logs sweep",
        description=f"Analyze all relevant log types in one pass: {', '.join(SWEEP_LOGS)}. "
                    "Plaintext to stdout by default; -o writes a combined markdown report.")
    parser.add_argument("-o", "--output",
                        help="Write combined markdown report to this path")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Full parameter lists in markdown output")
    _add_common_args(parser)
    args = parser.parse_args(argv)
    args.prefixes = _resolve_prefixes(args, cfg)
    args.no_rotation = False

    logs_dir = resolve_logs_dir(cfg)
    if not logs_dir.is_dir():
        print(f"Logs directory not found: {logs_dir}", file=sys.stderr)
        return 2

    findings = False
    out = open(args.output, "w", encoding="utf-8") if args.output else None

    try:
        for name in SWEEP_LOGS:
            result = _analyze_one(logs_dir, name, args)
            if result is None:
                continue
            meta, scored, actionable, suppressed = result
            if not meta["raw_line_count"]:
                continue
            if has_error_findings(actionable):
                findings = True
            if out:
                export_report(out, meta, scored, actionable, suppressed, verbose=args.verbose)
                out.write("\n\n")
            else:
                print("=" * 70)
                print_plaintext(meta, scored, actionable, suppressed)
    finally:
        if out:
            out.close()
            print(f"Combined report saved to: {args.output}")

    return 1 if findings else 0


def cmd_grep(argv, cfg):
    parser = argparse.ArgumentParser(
        prog="pdx-logs grep",
        description="Pull mod script-log lines (debug_log/error_log output) "
                    "matching PREFIX across debug.log and the error rotation "
                    "set, as one chronological stream.")
    parser.add_argument("prefix", help="Substring to match (e.g. SGD, SWL)")
    parser.add_argument("--logs", default="debug,error",
                        help="Comma-separated log names to search (default: debug,error)")
    parser.add_argument("-n", "--limit", type=int, default=0,
                        help="Show only the last N matches (default: all)")
    parser.add_argument("--all-sessions", action="store_true",
                        help="Include previous sessions (default: current session only)")
    args = parser.parse_args(argv)

    logs_dir = resolve_logs_dir(cfg)
    entries = []
    total_lines = 0
    skipped_all = []

    for name in [n.strip() for n in args.logs.split(",") if n.strip()]:
        label, paths = resolve_log_set(logs_dir, name)
        if not paths:
            continue
        files, skipped, session_secs, _ = _session_scope(
            logs_dir, paths, args.all_sessions)
        skipped_all.extend(skipped)
        gate_open = session_secs is None
        for path in files:
            try:
                f = open(path, encoding="utf-8-sig", errors="ignore")
            except OSError as e:
                print(f"WARNING: cannot read {path}: {e}", file=sys.stderr)
                continue
            with f:
                for line in f:
                    total_lines += 1
                    m = TIMESTAMP_RE.match(line.rstrip("\n\r"))
                    if not m:
                        continue
                    if not gate_open:
                        if _ts_to_secs(m.group(1)) >= session_secs:
                            gate_open = True
                        else:
                            continue
                    msg = m.group(3).strip()
                    if args.prefix in msg:
                        entries.append((_ts_to_secs(m.group(1)), m.group(1), path.name, msg))

    entries.sort(key=lambda e: e[0])
    shown = entries[-args.limit:] if args.limit else entries
    for _, ts, fname, msg in shown:
        print(f"[{ts}][{fname}] {msg}")
    scope = "all sessions" if args.all_sessions else "current session"
    summary = f"{len(entries)} matches for '{args.prefix}' ({scope}, {total_lines:,} lines scanned"
    if args.limit and len(shown) < len(entries):
        summary += f", showing last {len(shown)}"
    summary += ")"
    print(f"\n{summary}", file=sys.stderr)
    if skipped_all:
        print(f"Skipped (previous session): {', '.join(p.name for p in skipped_all)}",
              file=sys.stderr)
    return 0


def cmd_list(cfg):
    logs_dir = resolve_logs_dir(cfg)
    if not logs_dir.is_dir():
        print(f"Logs directory not found: {logs_dir}", file=sys.stderr)
        print("Set $PDX_LOG_DIR or 'logs_dir' in ~/.config/pdx-logs.json.", file=sys.stderr)
        return 2

    logs = sorted(f for f in logs_dir.iterdir() if f.suffix == ".log")
    if not logs:
        print(f"No .log files found in: {logs_dir}", file=sys.stderr)
        return 2

    session = detect_session_start(logs_dir)
    launch_epoch = session[1] if session else None

    print(f"Available logs in {logs_dir}:")
    if session:
        print(f"Current session: {session[2]}")
    print()
    for log in logs:
        size = log.stat().st_size
        if size < 1024:
            size_str = f"{size} B"
        elif size < 1024 * 1024:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size / (1024 * 1024):.1f} MB"
        marker = ""
        if launch_epoch and log.stat().st_mtime < launch_epoch - 5:
            marker = "  (previous session)"
        print(f"  {log.name:<40} {size_str:>10}{marker}")

    print("\nUsage: pdx-logs <log> [-p] | pdx-logs sweep | pdx-logs grep <PREFIX>")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    cfg = load_config()
    argv = sys.argv[1:]
    try:
        if argv and argv[0] == "sweep":
            return cmd_sweep(argv[1:], cfg)
        if argv and argv[0] == "grep":
            return cmd_grep(argv[1:], cfg)
        if argv and argv[0] == "list":
            return cmd_list(cfg)
        return cmd_analyze(argv, cfg)
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
