# eu5-logs

Error log analyzer for Europa Universalis 5. EU5 error logs regularly exceed 1000 lines, with critical mod-breaking issues buried among engine noise. Manually reading these was eating hours per debugging session and burning LLM context when delegated to AI assistants. This tool preprocesses logs into prioritized, actionable reports so diagnosis takes minutes instead of hours.

The parser uses a state machine to accumulate multi-line error blocks (jomini_script_system, pdx_persistent_reader) before matching them against 58 normalization patterns. Errors are grouped by pattern, scored by severity and frequency, and sorted by actionability. Known engine noise is suppressed to the bottom so real issues surface first.

## Install

```bash
pip install -e .
```

## Usage

```bash
eu5-logs                          # list available log files
eu5-logs error                    # analyze error.log, output markdown report
eu5-logs error -p                 # plaintext summary (compact, good for LLM consumption)
eu5-logs error -p -f sul_         # filter to mod-specific messages
eu5-logs error -v                 # full parameter lists, no truncation
eu5-logs error --no-suppress      # include known engine noise in actionable section
eu5-logs error --json             # machine-readable JSON output
eu5-logs game -p -t 10            # analyze game.log with 10-second timeout
```

## How It Works

1. **State machine parser** reads each log line and tracks whether it's inside a multi-line block (IDLE, SCRIPT_SYSTEM_ERROR, PERSISTENT_READER). Multi-line blocks are accumulated before pattern matching.
2. **58 normalization patterns** match parametric error messages and group them by root cause. `Missing Icon for Modifier : tax_1` and `Missing Icon for Modifier : army_2` become one group: "Missing Icon for Modifier" with a parameter list.
3. **Priority scoring** ranks groups by severity (error > warning > info) multiplied by instance count. Mod-specific errors (detected by configurable prefix filtering) get a score boost.
4. **Noise suppression** pushes known engine-level spam (texture format warnings, VFS path length, input context failures) to a separate section so they don't crowd out real issues.
5. **Output formats**: Markdown (default, for human reading), plaintext (compact, for LLM context), JSON (for tooling integration).

## Report Sections

- **Summary** — total messages, unique patterns, actionable vs suppressed counts
- **Actionable Errors** — priority-sorted groups with sample parameters
- **Suppressed Noise** — known engine messages, shown separately
- **Full Pattern Index** — every pattern seen, with counts

## Dependencies

- Python 3.9+
- No external dependencies
