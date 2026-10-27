# GreenLanTech design system for BreachGraph AI

The source of truth is GreenLanTech's published carousel artwork. Colours were **sampled from
the artwork pixels**. Typefaces were matched by eye and should be confirmed against the brand's
own font files. All values live in `frontend/src/styles/tokens.css`; components use only tokens.

## Colour

| Token | Hex | Sampled from | Used for |
|---|---|---|---|
| `--glt-forest` | `#0B3D2E` | dark slide background | sidebar, hero cards, graph frame |
| `--glt-lime` | `#B7FF3D` | logo square, highlight cards | primary buttons, active nav, step numbers, "verified/cut" accents |
| `--glt-paper` | `#F4F7F4` | light slide background | app background |
| `--glt-charcoal` | `#111916` | terminal bar | code / policy-statement blocks |
| `--glt-forest-chip` | `#235141` | inline code chips on dark | chips and selected states on forest |
| `--glt-forest-rule` | `#295B4D` | footer rule on dark | dividers on forest |
| `--ink` | `#131814` | body text on paper | body text |
| `--ink-muted` | `#3A4640` | footer text on paper | secondary text |
| `--on-dark-muted` | `#C5D8D2` | mono footer on dark | body text on forest |

Severity colours (critical `#B42318`, high `#B54708`, medium `#855F00`, low `#4B5A53`) are
functional additions. They are darkened so text on their tints meets WCAG AA. On the dark
graph canvas, coral `#FF7A6B` marks attack paths, and lime marks cuts made by a fix.

**Contrast:** all text pairs measured ≥ 4.5:1 (lowest: high-severity text on its tint, 4.85:1).

## Typography

- **Display: Space Grotesk** 500/700. Page titles and headings, like the slide headlines.
- **Body: Inter** 400/500/600.
- **Mono: JetBrains Mono** 400/500. Eyebrow labels (uppercase, wide tracking, like "THE CHANGE"),
  ids, scores, policy JSON.

Fonts are self-hosted (`@fontsource`). The app makes no third-party requests.

## Patterns taken from the brand artwork

| Artwork | Product |
|---|---|
| Mono uppercase eyebrow above a bold headline | every page header |
| Lime rounded square + two-tone wordmark | `BreachGraph AI` lockup, "by GreenLan**Tech**" |
| Charcoal terminal bar | policy-statement code blocks |
| Lime card with forest text ("RUNS") | primary actions, "verified" states |
| Forest card with lime eyebrow ("QUESTION FOR IDENTITY TEAMS") | highest-risk path card, success notices |
| Numbered lime steps `01 02 03` | verified evidence steps |
| Ruled table with heavy forest top rule | findings table |

## Provenance language

Readers must always be able to tell where content came from:

- **Verified by engine**: solid surfaces, shield-check label. Deterministic and reproducible.
- **AI-generated**: dashed border and sparkle label with provider, model and time. Not a new
  colour; the brand palette is kept.

## Motion

Only functional transitions (≤150 ms on hover/selection). A skeleton shimmer while loading.
Everything is disabled under `prefers-reduced-motion`.
