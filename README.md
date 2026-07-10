# pdx-logs

Log analyzer for Europa Universalis 5, and for other Clausewitz/Jomini titles that use the `[HH:MM:SS][source]:` log format. EU5 error logs rotate at about 1MB into `error.1.log` through `error.5.log`, mix multiple play sessions, and bury real mod-breaking errors in engine noise. pdx-logs stitches the full rotation set into one chronological stream, scopes it to the current game session, groups repeated errors into patterns, and reports them ranked by how actionable they are.

## Install

Self-contained Python script, no dependencies. Symlink it onto your PATH:

```bash
ln -s "$(pwd)/pdx_logs/cli.py" ~/.local/bin/pdx-logs
```

Point it at your logs directory with the `PDX_LOG_DIR` environment variable or `~/.config/pdx-logs.json` (see Configuration).

## Usage

```bash
pdx-logs                          # list available log files and the current session
pdx-logs error                    # analyze error.log plus its rotation set, write a markdown report
pdx-logs error -p                 # plaintext summary to stdout (compact, good for LLM consumption)
pdx-logs error -p -f sul_         # only messages containing "sul_"
pdx-logs error --all-sessions     # include previous sessions (default is current session only)
pdx-logs error --no-rotation      # just error.log, skip error.N.log
pdx-logs error -v                 # full parameter lists, no truncation
pdx-logs error --no-suppress      # include known engine noise in the main section
pdx-logs error --json             # machine-readable JSON output
pdx-logs game -p -t 10            # analyze game.log with a 10 second timeout

pdx-logs sweep                    # analyze error, game, debug, gui, database_conflicts in one pass
pdx-logs sweep -o report.md       # same, as one combined markdown report

pdx-logs grep SGD                 # mod script-log lines (debug_log/error_log output) for a prefix
pdx-logs grep SGD -n 50           # last 50 matches
pdx-logs grep SGD --logs debug    # search debug.log only
```

Exit codes: 0 clean, 1 error-severity findings present, 2 tool failure. An exit of 1 means the analysis ran fine and found errors, so hooks and CI can gate on it.

## How it works

1. **Rotation stitching.** `pdx-logs error` resolves `error.5.log` through `error.log` and parses them as one chronological stream. The engine rotates at about 1MB, so a single session's errors routinely span several files. Reading only `error.log` misses most of them, including startup validation errors, which fire first and rotate out first.
2. **Session scoping.** The most recent game launch is detected from the "Exe Git Version" line in `setup.log`, with the first line of `debug.log` as fallback. Files last written before the launch are skipped whole; within files that span the boundary, messages before the launch timestamp are gated out. `--all-sessions` disables the gate.
3. **Multi-line parsing.** A state machine accumulates multi-line error blocks before pattern matching. Lines in unknown multi-line formats attach to the preceding message instead of being dropped.
4. **Normalization.** 58 patterns match parametric error messages and group them by root cause, so a thousand "Missing Icon for Modifier : X" lines become one group with a parameter list. Matching keys on the engine source file name only, not its line number, so engine patches do not degrade categorization. Unmatched messages are generalized by masking numbers, quoted strings, and bracketed values before grouping.
5. **Scoring.** Groups are ranked by severity and instance count. Errors mentioning your mod prefixes get a boost.
6. **Noise suppression.** Known engine-level spam is collapsed into its own section.

## Configuration

`~/.config/pdx-logs.json`, all keys optional:

```json
{
  "logs_dir": "/path/to/Paradox Interactive/Europa Universalis V/logs",
  "prefixes": ["mymod_", "othermod_"]
}
```

`logs_dir` sets where the game writes logs; `$PDX_LOG_DIR` overrides it. `prefixes` are the mod namespaces that get a scoring boost; the `--prefix a_,b_` flag overrides per run.

## Report sections

- **Summary**: files parsed and skipped, session, message and group counts
- **Actionable Errors**: priority-sorted groups with sample parameters and locations
- **Suppressed Noise**: known engine messages, listed separately
- **Full Pattern Index**: every pattern seen, with counts

## Dependencies

Python 3.9+, standard library only.
