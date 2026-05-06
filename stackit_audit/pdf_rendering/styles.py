from __future__ import annotations

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm

_BASE = getSampleStyleSheet()

SEV_COLORS = {
    "critical": colors.HexColor("#C0392B"),
    "high":     colors.HexColor("#E67E22"),
    "medium":   colors.HexColor("#F1C40F"),
    "low":      colors.HexColor("#3498DB"),
    "info":     colors.HexColor("#95A5A6"),
}

STATUS_COLORS = {
    "FAIL":    colors.HexColor("#C0392B"),
    "PARTIAL": colors.HexColor("#E67E22"),
    "UNKNOWN": colors.HexColor("#F1C40F"),
    "PASS":    colors.HexColor("#27AE60"),
}

TITLE = ParagraphStyle(
    "AuditTitle",
    parent=_BASE["Title"],
    fontSize=22,
    spaceAfter=12,
)

HEADING1 = ParagraphStyle(
    "AuditH1",
    parent=_BASE["Heading1"],
    fontSize=14,
    spaceBefore=14,
    spaceAfter=6,
    textColor=colors.HexColor("#2C3E50"),
)

HEADING2 = ParagraphStyle(
    "AuditH2",
    parent=_BASE["Heading2"],
    fontSize=11,
    spaceBefore=10,
    spaceAfter=4,
    textColor=colors.HexColor("#34495E"),
)

BODY = ParagraphStyle(
    "AuditBody",
    parent=_BASE["Normal"],
    fontSize=9,
    leading=13,
    spaceAfter=4,
)

SMALL = ParagraphStyle(
    "AuditSmall",
    parent=_BASE["Normal"],
    fontSize=8,
    leading=11,
)

CODE = ParagraphStyle(
    "AuditCode",
    parent=_BASE["Code"],
    fontSize=8,
    leading=11,
    fontName="Courier",
)

TABLE_HEADER_BG = colors.HexColor("#2C3E50")
TABLE_HEADER_FG = colors.white
TABLE_ROW_ODD  = colors.HexColor("#ECF0F1")
TABLE_ROW_EVEN = colors.white

TABLE_STYLE_BASE = [
    ("BACKGROUND", (0, 0), (-1, 0), TABLE_HEADER_BG),
    ("TEXTCOLOR",  (0, 0), (-1, 0), TABLE_HEADER_FG),
    ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
    ("FONTSIZE",   (0, 0), (-1, -1), 8),
    ("LEADING",    (0, 0), (-1, -1), 10),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [TABLE_ROW_EVEN, TABLE_ROW_ODD]),
    ("GRID",       (0, 0), (-1, -1), 0.25, colors.HexColor("#BDC3C7")),
    ("VALIGN",     (0, 0), (-1, -1), "TOP"),
    ("LEFTPADDING",  (0, 0), (-1, -1), 4),
    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ("TOPPADDING",   (0, 0), (-1, -1), 3),
    ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
]
