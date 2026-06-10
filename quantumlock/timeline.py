"""Render a forged-vs-true timeline as a standalone SVG.

A timestomp is most legible as a picture: the displayed ($SI) timestamps sit far
in the past while the out-of-band record shows the real, recent activity. This
draws two lanes on a shared time axis and shades the gap the forgery opened. No
dependencies -- it returns an SVG string that renders inline on GitHub.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class Marker:
    at: float  # epoch seconds
    label: str


def _date(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d")


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_timeline(
    lanes: list[tuple[str, list[Marker]]],
    *,
    title: str = "",
    highlight: tuple[float, float, str] | None = None,
    width: int = 760,
) -> str:
    """Render labelled lanes of markers on a shared time axis."""
    times = [m.at for _, markers in lanes for m in markers]
    if highlight:
        times += [highlight[0], highlight[1]]
    lo, hi = min(times), max(times)
    span = (hi - lo) or 1.0
    left, right = 150, width - 40
    lane_h, top = 70, 60

    def x(t: float) -> float:
        return left + (t - lo) / span * (right - left)

    height = top + lane_h * len(lanes) + 40
    out: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'font-family="ui-monospace,Menlo,monospace" font-size="13">',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
    ]
    if title:
        out.append(f'<text x="20" y="30" font-size="16" font-weight="bold">{_esc(title)}</text>')

    if highlight:
        a, b, lbl = highlight
        x0, x1 = x(a), x(b)
        out.append(
            f'<rect x="{x0:.1f}" y="{top - 10:.1f}" width="{x1 - x0:.1f}" '
            f'height="{lane_h * len(lanes):.1f}" fill="#e44" opacity="0.10"/>'
        )
        out.append(
            f'<text x="{(x0 + x1) / 2:.1f}" y="{top - 18:.1f}" fill="#c33" '
            f'text-anchor="middle">{_esc(lbl)}</text>'
        )

    palette = ["#c0392b", "#27ae60", "#2980b9", "#8e44ad"]
    for i, (name, markers) in enumerate(lanes):
        y = top + lane_h * i + lane_h / 2
        color = palette[i % len(palette)]
        out.append(f'<text x="20" y="{y + 4:.1f}" fill="#333">{_esc(name)}</text>')
        out.append(f'<line x1="{left}" y1="{y:.1f}" x2="{right}" y2="{y:.1f}" stroke="#ccc"/>')
        for m in markers:
            mx = x(m.at)
            out.append(f'<circle cx="{mx:.1f}" cy="{y:.1f}" r="5" fill="{color}"/>')
            out.append(
                f'<text x="{mx:.1f}" y="{y - 12:.1f}" text-anchor="middle" fill="{color}">'
                f'{_esc(m.label)}</text>'
            )
            out.append(
                f'<text x="{mx:.1f}" y="{y + 22:.1f}" text-anchor="middle" fill="#888" '
                f'font-size="11">{_date(m.at)}</text>'
            )
    out.append("</svg>")
    return "\n".join(out)


def divergence_svg(
    file_id: str,
    displayed_created: float,
    displayed_modified: float,
    true_birth: float,
    true_last_write: float,
) -> str:
    """Convenience: the canonical timestomp picture for one file."""
    lanes = [
        (
            "Displayed $SI",
            [Marker(displayed_created, "created"), Marker(displayed_modified, "modified")],
        ),
        (
            "Out-of-band record",
            [Marker(true_birth, "birth"), Marker(true_last_write, "last write")],
        ),
    ]
    return render_timeline(
        lanes,
        title=f"Timestomp on {file_id}: displayed times predate the recorded truth",
        highlight=(displayed_modified, true_last_write, "forged backdate"),
    )
