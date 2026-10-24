# deRoute Brand Assets

Visual system for **deRoute** (short for decentralized-encrypted route), a private AI router where your device checks the seal on a locked computer before sending your message. The art direction follows an e-paper field-notebook aesthetic: crisp black ink line work and living ink blots on warm off-white paper with a single signal-orange focal point per composition.

## Files

- `drouter-mark.svg`: Primary geometric mark (lowercase `d` formed by a sealed computer ring, an ingress trace, and a single orange core). Designed to read clearly from `16 px` browser tabs to `512 px` app icons.
- `drouter-wordmark.svg`: Horizontal lockup combining the mark, serif display wordmark (`deRoute`), and monospace descriptor.
- `drouter-cover.svg` / `drouter-cover.png`: `1600 x 900` hero cover diagram illustrating how your device hides personal details, makes every message look the same size, and locks it so only the sealed computer can open it.
- `drouter-og.svg`: `1200 x 630` OpenGraph and social preview card.

## Color Palette

| Role | Hex | Usage |
| :--- | :--- | :--- |
| Paper | `#f3f1ec` | Primary background and knockouts |
| Secondary Paper | `#ebe8e1` | Spec callout insets |
| Primary Ink | `#151515` | Primary line art, display type, verified badges |
| Secondary Ink | `#3a3936` | Subheadings and callouts |
| Muted Ink | `#595752` | Monospace metadata, captions, and boundaries |
| Hairline Rule | `#d6d2c8` | Structural dividers and notebook borders |
| Signal Orange | `#d9531e` | Reserved for **one element per image** (the private prompt inside the sealed computer) |

## Clear Space & Minimum Size

- **Clear space**: Maintain a minimum clear margin of `25%` of the mark's height on all sides (`1/4` of mark width around `drouter-mark.svg`, or the cap-height of the `d` around `drouter-wordmark.svg`).
- **Minimum size**:
  - `drouter-mark.svg`: `16 x 16 px` minimum for digital UI and favicons.
  - `drouter-wordmark.svg`: `140 px` minimum width so the monospace tag remains legible (below `140 px`, use `drouter-mark.svg` alone).
- **Stroke & color discipline**: Never add gradients, drop shadows, glows, or a second orange accent to any composition.

## PNG exports

- `drouter-mark.png`: 1024 x 1024, transparent outside the tile.
- `drouter-wordmark.png`: 2112 x 432 (3x of the 704 x 144 SVG), transparent corners.

Re-export from the SVGs with headless Chrome if either SVG changes.
