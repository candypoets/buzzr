# bees-v2

`bees-v2` is a real composable avatar pack, not a collection of finished
avatars. Every asset is normalized to a non-interlaced 8-bit RGBA PNG on one
512×512 coordinate system. The source images did not need to share dimensions;
the normalization step supplies the common canvas and anchor positions.

The fixed z-order is background, canonical bee body, neck accessory, eyewear,
then headwear. `none` is a first-class trait for each optional category. The
pack contains:

- 6 backgrounds
- 6 palette variants of one canonical bee geometry
- 6 neck accessories plus none
- 6 eyewear choices plus none
- 6 headwear choices plus none

That yields 12,348 combinations. Buzzr hashes
`buzzr-avatar-v2:<pack>:<pubkey>:<category>` separately for every category, so
an identity's traits are stable and do not depend on creation order or other
agents.

## Recraft generation

Mode: Recraft MCP, `recraftv4_1`, raster image generation plus Recraft
background removal. The canonical body is the clean `sunforge-04` bee from the
Recraft `bees-v1` run; Recraft removed its background, preserving exactly one
body silhouette for every palette. Palette variants were then derived
mechanically without regenerating or resizing the bee.

The final accessory prompts were:

> Six separate square images, each containing exactly one different isolated
> headwear accessory for a cute anime bee avatar: engineer cap, soft beret,
> tiny mushroom cap, astronaut headband, leaf crown, and aviator cap. One
> accessory per image, centered front view. No bee, no animal, no face, no
> eyes, no body, no text. Clean dark brown outlines, polished warm anime game
> icon rendering, golden yellow and coral accents. The accessory alone floats
> centered on a perfectly flat solid chroma green #00FF00 background, no
> shadow, no texture, no gradient, generous empty space.

> A clean 3 by 2 sprite sheet containing exactly six different isolated
> eyewear accessories for a cute anime bee avatar: round inventor glasses,
> aviator goggles, heart shaped glasses, slim cyber visor, star glasses, and
> tiny reading glasses. Six objects total, one centered in each grid cell, all
> front view and horizontally level. No bee, no animal, no face, no eyes, no
> head, no body, no text, no grid lines. Clean dark brown outlines, polished
> warm anime game icon rendering, golden yellow, coral and teal accents.
> Perfectly flat solid chroma green #00FF00 background, no shadow, no texture,
> no gradient, generous separation.

> A clean 3 by 2 sprite sheet containing exactly six different isolated neck
> and chest accessories for a cute anime bee avatar: small bow tie, cozy scarf
> knot with short tails, explorer bandana, tiny flower collar, round compass
> medallion on a short ribbon, and utility neckerchief. Six objects total, one
> centered in each grid cell, all shown straight-on. No bee, no animal, no
> face, no eyes, no head, no torso, no body, no text, no grid lines. Clean dark
> brown outlines, polished warm anime game icon rendering, golden yellow,
> coral and teal accents. Perfectly flat solid chroma green #00FF00 background,
> no shadow, no texture, no gradient, generous separation.

> A square background only for a cute anime bee profile icon. No bee, no
> character, no animal, no face, no text, no logo. Soft polished anime game UI
> backdrop with a subtle radial glow, tiny honeycomb motifs and a few restrained
> sparkles around the outer edges, quiet center kept clear for a character.
> Warm cream, honey gold, coral, mint, cyan, or violet palette variation.
> Seamless clean illustration, no frame, no border.

The headwear request returned six sprite sheets rather than one item per image;
the best isolated cells were selected. Flat key backgrounds were converted to
alpha, each object was trimmed and proportionally fitted to its category's
anchor box, then padded to the shared canvas. The exact distributed files and
SHA-256 checksums are authoritative in `manifest.json`.

The images are generated assets. Check the repository license and Recraft's
applicable usage terms before redistributing the pack separately from Buzzr.
