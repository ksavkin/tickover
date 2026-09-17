# Design decisions

**Direction — "terminal instrument."** The panel speaks in the same monospace
voice as the CLI it monitors: a quiet, dark telemetry card, one accent, precise
numbers. Each meter is a captioned block: figure to the right, full-width bar,
reset time beneath — never a columnar table.

## Palette

Off-black surfaces, never pure black, with hairline borders and one status
accent that shifts by severity — mint below 70%, amber from 70 to 89%, red at
90% and above. The accent is locked panel-wide; the only decorative element is
a single semantic "live" dot.

| Role | Hex |
|---|---|
| Window | transparent — the card itself, not a background fill, reads as the panel |
| Panel | `#111419` |
| Panel top (header gradient) | `#14181f` |
| Surface (card rows) | `#171b22` |
| Meter track | `#20252e` |
| Hairline | `#262b34` |
| Hairline, strong | `#333a45` |
| Text | `#e7eaf0` |
| Dim text | `#9aa3b2` |
| Faint text | `#626b7a` |
| Accent, mint (< 70%) | `#3ddc97` |
| Accent, amber (70–89%) | `#f4b740` |
| Accent, red (≥ 90%) | `#f26d6d` |

## Typography

The platform's **native monospace** (Menlo on macOS, Consolas on Windows),
set once as the window's default font and inherited by every label.
Monospace gives tabular figures so the ticking countdown never shifts width,
and using the OS font keeps it native and dependency-free. Hierarchy comes
from weight, size and letter-spacing, not extra fonts — the sizes in use run
from 14px down to 8.5px across figures, labels and captions.

## Meters

Pill-shaped tracks with a gradient fill and a soft accent glow; the fill
width animates (700ms `ease-out-quart`) when a reading changes; a tiny
minimum width keeps low percentages visible.

## States

Every element has enabled / hover / checked states (custom checkbox, ghost
buttons, info dot with a hover tooltip), plus real empty states for *not
installed* and *no data yet*.

## Motion

Restrained on purpose: the countdown tick and the bar easing are the only
motion. No neon, no gratuitous animation.
