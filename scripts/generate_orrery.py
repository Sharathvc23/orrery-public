#!/usr/bin/env python3
"""
generate_orrery.py — emit an animated SVG orrery for the README.

Why this exists
---------------
GitHub strips inline <svg> from Markdown, but it *will* render an animated SVG
that is referenced as an image (`![](assets/orrery.svg)`). SMIL animation
(`<animateTransform>`) runs in that context with no JS, no build step, and works
offline — which is exactly the spirit of this project.

Accuracy model
--------------
A real orrery is a *scaled* clockwork model, not a 1:1 copy. We keep it honest:

  1. Orbit radii come from the planets' real semi-major axes (AU), compressed with
     a square-root law so the inner planets don't collapse into the Sun and the
     outer planets still fit the frame.  R_px = R0 + K * sqrt(a_AU).

  2. Orbital periods are then *recomputed from the displayed radii* using Kepler's
     third law, T ∝ R^1.5.  This makes the thing on screen a genuine, internally
     self-consistent Kepler system: what you watch obeys real orbital mechanics,
     it's just a smaller universe.  (Using the planets' true periods directly would
     be valid too, but Neptune's 165-year year makes it visually frozen — so we
     model a faithfully-scaled system instead of a faithfully-slow one.)

  3. Lighting is physical too: every body is shaded from the Sun.  Because the whole
     orbit group rotates rigidly about the centre, the planet→Sun direction is
     constant in the group's local frame, so a fixed terminator gradient stays
     correctly sun-lit through the entire orbit — no per-frame work needed.

  4. Relative body sizes, colours, atmospheres, Saturn's ring, and Earth's Moon are
     included for legibility, not metric accuracy — the same compromise every
     physical orrery makes.

Run:  python3 scripts/generate_orrery.py > assets/orrery.svg
"""

import math
import random
import sys

# ---------------------------------------------------------------------------
# Real data.  a_AU = semi-major axis (astronomical units).  size = display radius
# hint (px), roughly tracking true relative diameters but compressed.  Colours are
# eyeballed from spacecraft imagery.  atmo = optional rim-halo colour.
# ---------------------------------------------------------------------------
PLANETS = [
    # name        a_AU     size  core_color   glow_color   phase  atmo
    ("Mercury",   0.387,   4.0,  "#9c9088",   "#cdc3b8",     0,   None),
    ("Venus",     0.723,   7.0,  "#e6c479",   "#f7 ", 0, None),  # placeholder fixed below
    ("Earth",     1.000,   7.6,  "#3f86d6",   "#9fd0ff",    95,   "#7ab8ff"),
    ("Mars",      1.524,   5.2,  "#d05a36",   "#f2906f",   150,   None),
    ("Jupiter",   5.203,  16.0,  "#d3a06a",   "#eecfa1",   210,   None),
    ("Saturn",    9.537,  13.5,  "#e0c886",   "#f4e6bd",   285,   None),
    ("Uranus",   19.191,  10.0,  "#9fdce0",   "#cdf3f5",   330,   "#bfeef0"),
    ("Neptune",  30.070,  10.0,  "#4863d4",   "#90a6f6",    20,   "#7d93f0"),
]
# fix the placeholder cleanly (kept the table readable above)
PLANETS[1] = ("Venus", 0.723, 7.0, "#e6c479", "#f6e4ad", 40, "#f0d99a")

# Canvas / mapping ----------------------------------------------------------
SIZE = 920                      # square viewBox
CX = CY = SIZE / 2             # centre (the Sun, the "org")
R0 = 56                         # radius of innermost mapping offset (px)
K = 63.5                        # sqrt compression gain (px per sqrt(AU))
SUN_R = 25                      # Sun display radius

# Time scaling: innermost orbit takes BASE_DUR seconds; everything else follows
# Kepler from its displayed radius.
BASE_DUR = 7.0


def orbit_radius(a_au: float) -> float:
    """Real AU -> compressed pixel radius (sqrt law)."""
    return R0 + K * math.sqrt(a_au)


def kepler_duration(r_px: float, r_inner_px: float) -> float:
    """Displayed period from displayed radius: T = BASE * (R/R_inner)^1.5."""
    return BASE_DUR * (r_px / r_inner_px) ** 1.5


def starfield(n: int = 150, seed: int = 7) -> str:
    """Deterministic background stars + a few bright glints (seeded -> reproducible)."""
    rng = random.Random(seed)
    out, glints = [], []
    for _ in range(n):
        x, y = rng.uniform(0, SIZE), rng.uniform(0, SIZE)
        if math.hypot(x - CX, y - CY) < SUN_R + 16:
            continue
        r = rng.uniform(0.3, 1.4)
        o = rng.uniform(0.12, 0.85)
        tw = rng.uniform(2.5, 6.5)
        bo = rng.uniform(0, tw)
        tint = rng.choice(["#dfe8ff", "#dfe8ff", "#fff1d8", "#d8ecff"])
        out.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r:.2f}" fill="{tint}" opacity="{o:.2f}">'
            f'<animate attributeName="opacity" values="{o:.2f};{o*0.2:.2f};{o:.2f}" '
            f'dur="{tw:.1f}s" begin="-{bo:.1f}s" repeatCount="indefinite"/></circle>'
        )
    # a handful of brighter 4-point glint stars
    for _ in range(7):
        x, y = rng.uniform(60, SIZE - 60), rng.uniform(60, SIZE - 60)
        if math.hypot(x - CX, y - CY) < 150:
            continue
        s = rng.uniform(5, 9)
        tw = rng.uniform(3.5, 6.0)
        bo = rng.uniform(0, tw)
        glints.append(
            f'<g transform="translate({x:.1f} {y:.1f})" opacity="0.0">'
            f'<animate attributeName="opacity" values="0.15;0.9;0.15" dur="{tw:.1f}s" '
            f'begin="-{bo:.1f}s" repeatCount="indefinite"/>'
            f'<path d="M0 {-s:.1f} L0 {s:.1f} M{-s:.1f} 0 L{s:.1f} 0" stroke="#eaf2ff" '
            f'stroke-width="0.9" stroke-linecap="round"/>'
            f'<circle r="1.1" fill="#ffffff"/></g>'
        )
    return "\n  ".join(out + glints)


def saturn_ring(px, py, size) -> tuple:
    """Return (back, front) ring fragments so the planet sits *inside* the ring."""
    rx, ry = size * 2.15, size * 0.74
    tilt = -20
    g_open = f'<g transform="rotate({tilt} {px:.1f} {py:.1f})">'
    # back half (drawn before planet), front half (after) -> depth
    back = (
        f"{g_open}"
        f'<path d="M{px-rx:.1f} {py:.1f} A {rx:.1f} {ry:.1f} 0 0 1 {px+rx:.1f} {py:.1f}" '
        f'fill="none" stroke="url(#ring)" stroke-width="5.2" opacity="0.9"/></g>'
    )
    front = (
        f"{g_open}"
        f'<path d="M{px-rx:.1f} {py:.1f} A {rx:.1f} {ry:.1f} 0 0 0 {px+rx:.1f} {py:.1f}" '
        f'fill="none" stroke="url(#ring)" stroke-width="5.2" opacity="0.95"/>'
        f'<path d="M{px-rx*0.66:.1f} {py:.1f} A {rx*0.66:.1f} {ry*0.66:.1f} 0 0 0 {px+rx*0.66:.1f} {py:.1f}" '
        f'fill="none" stroke="#b89a5a" stroke-width="1.3" opacity="0.5"/></g>'
    )
    return back, front


def planet_group(name, a_au, size, core, glow, phase, atmo, r_px, dur) -> str:
    px, py = CX + r_px, CY
    grad = f"grad-{name.lower()}"
    begin = -(phase / 360.0) * dur  # negative begin = start mid-orbit (phase offset)

    pre, post = "", ""
    if name == "Saturn":
        b, f = saturn_ring(px, py, size)
        pre, post = b, f
    if name == "Earth":
        moon_r = size + 9
        moon_dur = max(2.2, dur * 0.28)
        post += (
            f'<g><animateTransform attributeName="transform" type="rotate" '
            f'from="0 {px:.1f} {py:.1f}" to="360 {px:.1f} {py:.1f}" '
            f'dur="{moon_dur:.1f}s" repeatCount="indefinite"/>'
            f'<circle cx="{px+moon_r:.1f}" cy="{py:.1f}" r="2.0" fill="#cfd3da"/></g>'
        )

    atmo_halo = ""
    if atmo:
        atmo_halo = (
            f'<circle cx="{px:.1f}" cy="{py:.1f}" r="{size*1.16:.1f}" fill="none" '
            f'stroke="{atmo}" stroke-width="2.1" opacity="0.35"/>'
        )

    # base body, sun-lit terminator, and a small specular glint toward the Sun (left)
    spec_x, spec_y, spec_r = px - size * 0.34, py - size * 0.30, size * 0.20
    body = (
        f'{atmo_halo}'
        f'<circle cx="{px:.1f}" cy="{py:.1f}" r="{size:.1f}" fill="url(#{grad})"/>'
        f'<circle cx="{px:.1f}" cy="{py:.1f}" r="{size:.1f}" fill="url(#shade)"/>'
        f'<ellipse cx="{spec_x:.1f}" cy="{spec_y:.1f}" rx="{spec_r:.1f}" ry="{spec_r*0.75:.1f}" '
        f'fill="#ffffff" opacity="0.35"/>'
    )

    return f"""  <!-- {name}: a={a_au} AU  R={r_px:.1f}px  T={dur:.1f}s -->
  <circle cx="{CX}" cy="{CY}" r="{r_px:.1f}" fill="none" stroke="#26324c" stroke-width="1" opacity="0.5"/>
  <g>
    <animateTransform attributeName="transform" type="rotate"
      from="0 {CX} {CY}" to="360 {CX} {CY}" dur="{dur:.1f}s"
      begin="{begin:.2f}s" repeatCount="indefinite"/>
    {pre}
    {body}
    {post}
  </g>"""


def planet_gradient(name, core, glow) -> str:
    # highlight focal point sits toward the Sun (left side of the body)
    return (
        f'<radialGradient id="grad-{name.lower()}" cx="32%" cy="40%" r="78%">'
        f'<stop offset="0%" stop-color="{glow}"/>'
        f'<stop offset="55%" stop-color="{core}"/>'
        f'<stop offset="100%" stop-color="{core}" stop-opacity="0.9"/>'
        f"</radialGradient>"
    )


def build() -> str:
    r_inner = orbit_radius(PLANETS[0][1])
    gradients = "\n    ".join(planet_gradient(p[0], p[3], p[4]) for p in PLANETS)
    groups = []
    for name, a_au, size, core, glow, phase, atmo in PLANETS:
        r_px = orbit_radius(a_au)
        dur = kepler_duration(r_px, r_inner)
        groups.append(planet_group(name, a_au, size, core, glow, phase, atmo, r_px, dur))
    bodies = "\n".join(groups)

    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {SIZE} {SIZE}"
     width="{SIZE}" height="{SIZE}" role="img"
     aria-label="Animated orrery: eight sun-lit planets revolving around a central star, periods following Kepler's third law">
  <title>Orrery — a clockwork model of a star system</title>
  <desc>A scaled Kepler system. Orbit radii are the planets' real semi-major axes
  (sqrt-compressed); periods are recomputed from the displayed radii so the motion
  obeys T proportional to R^1.5. Every body is shaded from the Sun. Pure SMIL, no script.</desc>

  <defs>
    <radialGradient id="space" cx="50%" cy="46%" r="72%">
      <stop offset="0%" stop-color="#121d3a"/>
      <stop offset="55%" stop-color="#0a0e1f"/>
      <stop offset="100%" stop-color="#04050b"/>
    </radialGradient>
    <radialGradient id="vignette" cx="50%" cy="50%" r="62%">
      <stop offset="0%" stop-color="#000000" stop-opacity="0"/>
      <stop offset="78%" stop-color="#000000" stop-opacity="0"/>
      <stop offset="100%" stop-color="#000000" stop-opacity="0.55"/>
    </radialGradient>
    <radialGradient id="sun" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#fff7d6"/>
      <stop offset="45%" stop-color="#ffd066"/>
      <stop offset="100%" stop-color="#ff8a1e"/>
    </radialGradient>
    <radialGradient id="corona" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#ffb84d" stop-opacity="0.55"/>
      <stop offset="100%" stop-color="#ffb84d" stop-opacity="0"/>
    </radialGradient>
    <linearGradient id="shade" x1="0" y1="0" x2="1" y2="0.12">
      <stop offset="38%" stop-color="#04050a" stop-opacity="0"/>
      <stop offset="100%" stop-color="#04050a" stop-opacity="0.58"/>
    </linearGradient>
    <linearGradient id="ring" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0%" stop-color="#d8c089" stop-opacity="0.2"/>
      <stop offset="25%" stop-color="#efdca6" stop-opacity="0.95"/>
      <stop offset="50%" stop-color="#c9ad6c" stop-opacity="1"/>
      <stop offset="75%" stop-color="#efdca6" stop-opacity="0.95"/>
      <stop offset="100%" stop-color="#d8c089" stop-opacity="0.2"/>
    </linearGradient>
    {gradients}
  </defs>

  <!-- backdrop -->
  <rect width="{SIZE}" height="{SIZE}" fill="url(#space)"/>
  {starfield()}

  <!-- corona + star -->
  <circle cx="{CX}" cy="{CY}" r="{SUN_R*3.2:.0f}" fill="url(#corona)">
    <animate attributeName="r" values="{SUN_R*3.0:.0f};{SUN_R*3.5:.0f};{SUN_R*3.0:.0f}"
      dur="6s" repeatCount="indefinite"/>
    <animate attributeName="opacity" values="0.85;1;0.85" dur="6s" repeatCount="indefinite"/>
  </circle>
  <circle cx="{CX}" cy="{CY}" r="{SUN_R}" fill="url(#sun)"/>

  <!-- planets -->
{bodies}

  <!-- depth -->
  <rect width="{SIZE}" height="{SIZE}" fill="url(#vignette)"/>
</svg>
"""


if __name__ == "__main__":
    sys.stdout.write(build())
