import xml.dom.minidom

from quantumlock.timeline import Marker, divergence_svg, render_timeline


def test_render_timeline_is_well_formed_svg():
    svg = render_timeline(
        [("lane A", [Marker(1.0, "a"), Marker(5.0, "b")])],
        title="t",
        highlight=(1.0, 5.0, "gap"),
    )
    # parses as XML and is an <svg> root
    doc = xml.dom.minidom.parseString(svg)
    assert doc.documentElement.tagName == "svg"


def test_divergence_svg_contains_both_lanes_and_the_gap():
    svg = divergence_svg("evil.exe", 1.0e9, 1.0e9, 1.7e9, 1.7e9 + 400)
    assert "Displayed $SI".replace("$", "$") in svg  # lane label present
    assert "Out-of-band record" in svg
    assert "forged backdate" in svg
    xml.dom.minidom.parseString(svg)  # well-formed


def test_escaping_keeps_svg_valid():
    svg = render_timeline([("a & <b>", [Marker(0.0, "<m>")])])
    assert "&amp;" in svg and "&lt;" in svg
    xml.dom.minidom.parseString(svg)
