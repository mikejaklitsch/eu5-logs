# pdx-logs

Log analyzer for Europa Universalis 5 (and other Clausewitz/Jomini titles using the `[HH:MM:SS][source]:` log format). EU5 error logs regularly exceed 1000 lines, rotate at ~1MB into `error.1.log` through `error.5.log`, and mix multiple play sessions, with critical mod-breaking issues buried among engine noise. This tool stitches the full rotation set into one chronological stream, scopes it to the current game session, and preprocesses it into prioritized, actionable reports so diagnosis takes minutes instead of hours.

The parser uses a state machine to accumulate multi-line error blocks (jomini_script_system, pdx_persistent_reader) before matching them against 58 normalization patterns. Errors are grouped by pattern, scored by severity and frequency, and sorted by actionability. Known engine noise is suppressed to the bottom so real issues surface first. Unmatched messages are generalized (numbers, quoted strings, and bracketed values masked) so near-identical variants collapse into one group instead of exploding the report.

## Install

```bash
pip install -e .
```

Installs the `pdx-logs` command. Point it at your logs directory via the `PDX_LOG_DIR` environment variable or `~/.config/pdx-logs.json` (see Configuration); without either it falls back to the author's path.

## Usage

```bash
pdx-logs                          # list available log files + current session
pdx-logs error                    # analyze error.log + its rotation set, markdown report
pdx-logs error -p                 # plaintext summary (compact, good for LLM consumption)
pdx-logs error -p -f sul_         # filter to mod-specific messages
pdx-logs error --all-sessions     # include previous sessions (default: current only)
pdx-logs error --no-rotation      # just error.log, skip error.N.log
pdx-logs error -v                 # full parameter lists, no truncation
pdx-logs error --no-suppress      # include known engine noise in actionable section
pdx-logs error --json             # machine-readable JSON output
pdx-logs game -p -t 10            # analyze game.log with 10-second timeout

pdx-logs sweep                    # analyze error, game, debug, gui, database_conflicts in one pass
pdx-logs sweep -o report.md       # combined markdown report

pdx-logs grep SGD                 # mod script-log lines (debug_log/error_log output)
pdx-logs grep SGD -n 50           # last 50 matches
pdx-logs grep SGD --logs debug    # search debug.log only
```

Exit codes: `0` clean, `1` error-severity findings present, `2` tool failure. A `1` means the analysis ran fine and found errors; hooks and CI can gate on it.

## How It Works

1. **Rotation stitching**: `pdx-logs error` resolves `error.5.log` → ... → `error.1.log` → `error.log` and parses them as one chronological stream. The engine rotates at ~1MB, so a single session's errors routinely span several files; reading only `error.log` misses most of them (including startup validation errors, which fire first and rotate out first).
2. **Session scoping**: the most recent game launch is detected from `setup.log`'s "Exe Git Version" line (fallback: `debug.log`'s first line). Files last written before the launch are skipped whole; within spanning files, messages before the launch timestamp are gated out. Default scope is the current session; `--all-sessions` widens.
3. **State machine parser** accumulates multi-line blocks before pattern matching. Lines in unknown multi-line formats attach to the preceding message instead of being dropped.
4. **58 normalization patterns** match parametric error messages and group them by root cause. Matching is on engine source file name only (not line number), so engine patches don't silently degrade categorization.
5. **Priority scoring** ranks groups by severity and instance count. Mod-specific errors get a boost, detected by configurable prefixes.
6. **Noise suppression** pushes known engine-level spam to a separate section.
7. **Output formats**: Markdown (default, written to the current directory), plaintext (compact, for LLM context), JSON (for tooling).

## Configuration

`~/.config/pdx-logs.json` (all keys optional):

```json
{
  "logs_dir": "/mnt/c/Users/you/Documents/Paradox Interactive/Europa Universalis V/logs",
  "prefixes": ["mymod_", "othermod_"]
}
```

- `logs_dir` — where the game writes logs. `$PDX_LOG_DIR` overrides it.
- `prefixes` — mod namespace prefixes that get a priority boost in scoring (default `sul_`, `epbm_`). The `--prefix a_,b_` flag overrides per run.

## Report Sections

- **Summary** — files parsed/skipped, session, total messages, actionable vs suppressed counts
- **Actionable Errors** — priority-sorted groups with sample parameters
- **Suppressed Noise** — known engine messages, shown separately
- **Full Pattern Index** — every pattern seen, with counts

## Dependencies

- Python 3.9+
- No external dependencies
