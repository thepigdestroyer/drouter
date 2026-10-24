# dRouter Brand Assets

Visual system for **dRouter**, a hardware-attested confidential AI router. The art direction follows an e-paper field-notebook aesthetic: crisp black ink line work on warm off-white paper with a single signal-orange focal point per composition.

## Files

- `drouter-mark.svg`: Primary geometric mark (lowercase `d` formed by a sealed enclave ring, an ingress trace, and a single orange core). Designed to read clearly from `16 px` browser tabs to `512 px` app icons.
- `drouter-wordmark.svg`: Horizontal lockup combining the mark, serif display wordmark, and monospace descriptor.
- `drouter-cover.svg` / `drouter-cover.png`: `1600 x 900` hero cover diagram illustrating client-side scrubbing/padding/encryption, fixed-size relay ciphertext frames, and decryption inside attested TEE hardware.

## Color Palette

| Role | Hex | Usage |
| :--- | :--- | :--- |
| Paper | `#f3f1ec` | Primary background and knockouts |
| Secondary Paper | `#ebe8e1` | Spec callout insets |
| Primary Ink | `#151515` | Primary line art, display type, verified badges |
| Secondary Ink | `#3f3e3b` | Subheadings and technical callouts |
| Muted Ink | `#6e6c67` | Monospace metadata, captions, and untrusted boundaries |
| Hairline Rule | `#d6d2c8` | Structural dividers and notebook borders |
| Signal Orange | `#d9531e` | Reserved for **one element per image** (the confidential prompt inside the sealed enclave) |

## Clear Space & Minimum Size

- **Clear space**: Maintain a minimum clear margin of `25%` of the mark's height on all sides (`1/4` of mark width around `drouter-mark.svg`, or the cap-height of the `d` around `drouter-wordmark.svg`).
- **Minimum size**:
  - `drouter-mark.svg`: `16 x 16 px` minimum for digital UI and favicons.
  - `drouter-wordmark.svg`: `140 px` minimum width so the monospace tag remains legible (below `140 px`, use `drouter-mark.svg` alone).
- **Stroke & color discipline**: Never add gradients, drop shadows, glows, or a second orange accent to any composition.
