"""Build local PhishLens PDF security reports from stored scan data.

Reports use saved analysis results only. They do not reopen URLs, reread
email bodies, or call external services.
"""

from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Flowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from config.scoring_rules import BASE_SCORE
from services.combined_assessment import assess_scan_record
from time_format import format_bahrain_datetime

PAGE_WIDTH, _PAGE_HEIGHT = A4
LEFT_MARGIN = 18 * mm
RIGHT_MARGIN = 18 * mm
TOP_MARGIN = 16 * mm
BOTTOM_MARGIN = 18 * mm
USABLE_WIDTH = PAGE_WIDTH - LEFT_MARGIN - RIGHT_MARGIN

PURPLE = colors.HexColor("#8C56D4")
TEXT = colors.HexColor("#2D2140")
MUTED = colors.HexColor("#665A73")
LOW = colors.HexColor("#0F766E")
SUSPICIOUS = colors.HexColor("#B45309")
HIGH = colors.HexColor("#B91C1C")
LIGHT_BORDER = colors.HexColor("#EAD4FB")
LIGHT_BG = colors.HexColor("#FAF7FF")
LOW_FILL = colors.HexColor("#99F6E4")
SUSPICIOUS_FILL = colors.HexColor("#FDBA74")
HIGH_FILL = colors.HexColor("#FCA5A5")


def _text(value, fallback="Not present"):
    """Return plain text safe for ReportLab Paragraph markup."""
    if value is None:
        return fallback
    text = str(value).strip()
    if not text:
        return fallback
    return escape(text)


def _soft_break_url(value, fallback="Not present"):
    """Escape untrusted URL/evidence text for Paragraph use.

    Wrapping is handled by Paragraph wordWrap='CJK' on the value style so long
    URLs break inside the printable width without inserting extractable
    zero-width characters into the PDF text stream.
    """
    return _text(value, fallback)


def _format_report_date(value):
    """Show a stored ISO timestamp in Bahrain time for the PDF header."""
    return format_bahrain_datetime(value, missing="Unknown time")


def _classification_color(classification):
    label = (classification or "").strip().lower()
    if label in ("low risk", "low concern"):
        return LOW
    if label == "suspicious":
        return SUSPICIOUS
    return HIGH


def _table(data, col_widths, style_commands=None):
    """Build a table that never exceeds the printable width."""
    widths = list(col_widths)
    total = sum(widths)
    if total > USABLE_WIDTH and total > 0:
        scale = USABLE_WIDTH / total
        widths = [width * scale for width in widths]
    table = Table(data, colWidths=widths, hAlign="LEFT")
    commands = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]
    if style_commands:
        commands.extend(style_commands)
    table.setStyle(TableStyle(commands))
    return table


class RiskScoreBlock(Flowable):
    """Draw score + classification with fixed vertical positions (no overlap)."""

    def __init__(self, score, classification, width=None):
        super().__init__()
        try:
            self.score = max(0, min(100, int(score)))
        except (TypeError, ValueError):
            self.score = 0
        self.classification = str(classification or "Not present").strip() or "Not present"
        self.color = _classification_color(self.classification)
        self._width = width if width is not None else USABLE_WIDTH
        # Fixed band heights in points — large enough that glyphs cannot collide.
        self._heading_band = 18
        self._score_band = 40
        self._gap_band = 18
        self._class_band = 24
        self.width = self._width
        self.height = (
            self._heading_band + self._score_band + self._gap_band + self._class_band
        )

    def wrap(self, availWidth, availHeight):
        self.width = min(self._width, availWidth, USABLE_WIDTH)
        return self.width, self.height

    def draw(self):
        canvas = self.canv
        center_x = self.width / 2.0

        # Origin is bottom-left; draw from the top of this flowable downward.
        y = self.height - 14
        canvas.setFillColor(MUTED)
        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawCentredString(center_x, y, "Risk Score")

        y -= self._score_band
        canvas.setFillColor(TEXT)
        canvas.setFont("Helvetica-Bold", 28)
        canvas.drawCentredString(center_x, y, f"{self.score} / 100")

        y -= self._gap_band + 4
        canvas.setFillColor(self.color)
        canvas.setFont("Helvetica-Bold", 14)
        canvas.drawCentredString(center_x, y, self.classification.upper())


class RiskMeter(Flowable):
    """Printable risk meter sized to the A4 usable width."""

    def __init__(self, score, width=None, height=9):
        super().__init__()
        self.score = max(0, min(100, int(score or 0)))
        self.bar_width = width if width is not None else USABLE_WIDTH
        self.bar_height = height
        self.width = self.bar_width
        self.height = self.bar_height + 4

    def wrap(self, availWidth, availHeight):
        self.bar_width = min(self.bar_width, availWidth, USABLE_WIDTH)
        self.width = self.bar_width
        self.height = self.bar_height + 4
        return self.width, self.height

    def draw(self):
        low_w = self.bar_width * 0.30
        sus_w = self.bar_width * 0.30
        high_w = self.bar_width * 0.40
        y = 2

        self.canv.setFillColor(LOW_FILL)
        self.canv.roundRect(0, y, low_w, self.bar_height, 2.5, fill=1, stroke=0)
        self.canv.setFillColor(SUSPICIOUS_FILL)
        self.canv.rect(low_w, y, sus_w, self.bar_height, fill=1, stroke=0)
        self.canv.setFillColor(HIGH_FILL)
        self.canv.roundRect(
            low_w + sus_w, y, high_w, self.bar_height, 2.5, fill=1, stroke=0
        )

        radius = 3.5
        marker_x = (self.score / 100.0) * self.bar_width
        marker_x = max(radius, min(self.bar_width - radius, marker_x))
        self.canv.setFillColor(TEXT)
        self.canv.circle(marker_x, y + self.bar_height / 2.0, radius, fill=1, stroke=0)
        self.canv.setStrokeColor(colors.white)
        self.canv.setLineWidth(0.8)
        self.canv.circle(marker_x, y + self.bar_height / 2.0, radius, fill=0, stroke=1)


def _styles():
    base = getSampleStyleSheet()
    styles = {
        "brand": ParagraphStyle(
            "Brand",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=28,
            leading=32,
            textColor=PURPLE,
            spaceBefore=0,
            spaceAfter=2,
            alignment=TA_CENTER,
        ),
        "tagline": ParagraphStyle(
            "Tagline",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=12,
            leading=14,
            textColor=MUTED,
            spaceBefore=0,
            spaceAfter=8,
            alignment=TA_CENTER,
        ),
        "title": ParagraphStyle(
            "ReportTitle",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=TEXT,
            spaceBefore=0,
            spaceAfter=10,
            alignment=TA_CENTER,
        ),
        "h2": ParagraphStyle(
            "Section",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            textColor=PURPLE,
            spaceBefore=10,
            spaceAfter=5,
            keepWithNext=True,
        ),
        "h3": ParagraphStyle(
            "SubSection",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=TEXT,
            spaceBefore=6,
            spaceAfter=3,
            keepWithNext=True,
        ),
        "body": ParagraphStyle(
            "Body",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=TEXT,
            spaceAfter=3,
        ),
        "muted": ParagraphStyle(
            "Muted",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11,
            textColor=MUTED,
            spaceAfter=3,
        ),
        "label": ParagraphStyle(
            "Label",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=MUTED,
            spaceAfter=1,
        ),
        "meta_label": ParagraphStyle(
            "MetaLabel",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=11,
            textColor=MUTED,
        ),
        "meta_value": ParagraphStyle(
            "MetaValue",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=11,
            textColor=TEXT,
            wordWrap="CJK",
        ),
        "value": ParagraphStyle(
            "Value",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=TEXT,
            spaceAfter=4,
            wordWrap="CJK",
        ),
        "score_heading": ParagraphStyle(
            "ScoreHeading",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=MUTED,
            alignment=TA_CENTER,
            spaceBefore=0,
            spaceAfter=0,
        ),
        "score": ParagraphStyle(
            "Score",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=28,
            leading=34,
            textColor=TEXT,
            alignment=TA_CENTER,
            spaceBefore=0,
            spaceAfter=0,
        ),
        "class": ParagraphStyle(
            "Class",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            alignment=TA_CENTER,
            spaceBefore=0,
            spaceAfter=0,
        ),
        "meter_left": ParagraphStyle(
            "MeterLeft",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            textColor=MUTED,
            alignment=TA_LEFT,
        ),
        "meter_center": ParagraphStyle(
            "MeterCenter",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            textColor=MUTED,
            alignment=TA_CENTER,
        ),
        "meter_right": ParagraphStyle(
            "MeterRight",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            textColor=MUTED,
            alignment=TA_RIGHT,
        ),
    }
    return styles


def _add_footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(LIGHT_BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(LEFT_MARGIN, 12 * mm, PAGE_WIDTH - RIGHT_MARGIN, 12 * mm)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawString(
        LEFT_MARGIN,
        7 * mm,
        "PhishLens Security Analysis Report",
    )
    canvas.drawRightString(
        PAGE_WIDTH - RIGHT_MARGIN,
        7 * mm,
        f"Page {doc.page}",
    )
    canvas.restoreState()


def _metadata_table(styles, report_type, scan):
    analyzed = _format_report_date(scan.get("created_at"))
    rows = [
        [
            Paragraph("Report Type", styles["meta_label"]),
            Paragraph(_text(report_type), styles["meta_value"]),
        ],
        [
            Paragraph("Scan ID", styles["meta_label"]),
            Paragraph(f"#{_text(scan.get('id'), 'Not present')}", styles["meta_value"]),
        ],
        [
            Paragraph("Analysis Date", styles["meta_label"]),
            Paragraph(_text(analyzed), styles["meta_value"]),
        ],
    ]
    return _table(
        rows,
        [USABLE_WIDTH * 0.28, USABLE_WIDTH * 0.72],
        [
            ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
            ("BOX", (0, 0), (-1, -1), 0.5, LIGHT_BORDER),
            ("LINEBELOW", (0, 0), (-1, -2), 0.25, LIGHT_BORDER),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ],
    )


def _risk_section(styles, score, classification):
    """Compact risk score + meter kept together across page breaks."""
    label_row = _table(
        [
            [
                Paragraph("Low Risk", styles["meter_left"]),
                Paragraph("Suspicious", styles["meter_center"]),
                Paragraph("High Risk", styles["meter_right"]),
            ]
        ],
        [USABLE_WIDTH / 3.0, USABLE_WIDTH / 3.0, USABLE_WIDTH / 3.0],
        [
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ],
    )
    return KeepTogether(
        [
            RiskScoreBlock(score, classification, USABLE_WIDTH),
            Spacer(1, 12),
            RiskMeter(score, width=USABLE_WIDTH),
            Spacer(1, 4),
            label_row,
            Spacer(1, 8),
        ]
    )


def _header_block(styles, report_type, scan, score, classification):
    return [
        Paragraph("PhishLens", styles["brand"]),
        Paragraph("See the signals. Spot the risk.", styles["tagline"]),
        Paragraph("Security Analysis Report", styles["title"]),
        _metadata_table(styles, report_type, scan),
        Spacer(1, 10),
        _risk_section(styles, score, classification),
    ]


def _kv_table(styles, pairs):
    rows = []
    for label, value in pairs:
        rows.append(
            [
                Paragraph(_text(label), styles["meta_label"]),
                Paragraph(_text(value), styles["value"]),
            ]
        )
    return _table(
        rows,
        [USABLE_WIDTH * 0.28, USABLE_WIDTH * 0.72],
        [
            ("LINEBELOW", (0, 0), (-1, -2), 0.25, LIGHT_BORDER),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ],
    )


def _url_paragraph(styles, value):
    return Paragraph(_soft_break_url(value), styles["value"])


def _breakdown_table(styles, base_score, indicators, correlations, raw_score, final_score):
    rows = [
        [
            Paragraph("<b>Item</b>", styles["body"]),
            Paragraph("<b>Points</b>", styles["body"]),
        ]
    ]
    rows.append(
        [
            Paragraph("Base Score", styles["body"]),
            Paragraph(_text(base_score), styles["body"]),
        ]
    )
    rows.append([Paragraph("<b>Indicator Contributions</b>", styles["body"]), ""])
    if indicators:
        for item in indicators:
            rows.append(
                [
                    Paragraph(_text(item.get("title")), styles["body"]),
                    Paragraph(_format_points(item.get("score_change")), styles["body"]),
                ]
            )
    else:
        rows.append([Paragraph("None detected", styles["muted"]), ""])

    rows.append([Paragraph("<b>Correlation Factors</b>", styles["body"]), ""])
    if correlations:
        for item in correlations:
            rows.append(
                [
                    Paragraph(_text(item.get("title")), styles["body"]),
                    Paragraph(_format_points(item.get("score_change")), styles["body"]),
                ]
            )
    else:
        rows.append([Paragraph("None detected", styles["muted"]), ""])

    rows.append(
        [
            Paragraph("<b>Raw Score</b>", styles["body"]),
            Paragraph(_text(raw_score), styles["body"]),
        ]
    )
    rows.append(
        [
            Paragraph("<b>Final Risk Score</b>", styles["body"]),
            Paragraph(f"{_text(final_score)}/100", styles["body"]),
        ]
    )

    return _table(
        rows,
        [USABLE_WIDTH * 0.82, USABLE_WIDTH * 0.18],
        [
            ("BACKGROUND", (0, 0), (-1, 0), LIGHT_BG),
            ("TEXTCOLOR", (0, 0), (-1, -1), TEXT),
            ("BOX", (0, 0), (-1, -1), 0.5, LIGHT_BORDER),
            ("LINEBELOW", (0, 0), (-1, -2), 0.25, LIGHT_BORDER),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ],
    )


def _format_points(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return _text(value, "0")
    if number > 0:
        return f"+{number}"
    return str(number)


def _indicator_block(styles, item, include_severity=False):
    severity = (item.get("severity") or "").strip().upper() or "N/A"
    points = _format_points(item.get("score_change"))
    header = _table(
        [
            [
                Paragraph(_text(item.get("title")), styles["body"]),
                Paragraph(points, styles["body"]),
                Paragraph(severity if include_severity else "", styles["muted"]),
            ]
        ],
        [USABLE_WIDTH * 0.62, USABLE_WIDTH * 0.18, USABLE_WIDTH * 0.20],
        [
            ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
            ("BOX", (0, 0), (-1, -1), 0.4, LIGHT_BORDER),
            ("ALIGN", (1, 0), (2, 0), "RIGHT"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ],
    )
    block = [
        header,
        Paragraph(
            f"Explanation: {_text(item.get('explanation'), 'No explanation stored.')}",
            styles["body"],
        ),
    ]
    if item.get("evidence"):
        block.append(
            Paragraph(
                f"Evidence: {_soft_break_url(item.get('evidence'), _text(item.get('evidence')))}",
                styles["muted"],
            )
        )
    block.append(Spacer(1, 4))
    return KeepTogether(block)


def _methodology(styles, kind):
    lines = [
        "PhishLens uses rule-based heuristic analysis.",
        "Risk scores are not probabilities.",
        "Low Risk does not guarantee safety.",
        "High Risk does not prove maliciousness.",
    ]
    if kind == "url":
        lines.extend(
            [
                "URLs are analyzed locally as text. Optional external reputation "
                "lookups are separate evidence and do not change local scores.",
                "External reputation results reflect provider data available at "
                "the time of the check.",
                "No detections from a reputation provider does not guarantee "
                "that a URL is safe.",
            ]
        )
    else:
        lines.extend(
            [
                "Email authentication values from supplied headers are not "
                "independently verified.",
                "No attachment malware execution or scanning occurs.",
                "PhishLens does not retain the complete email body or attachment "
                "contents in historical analysis records.",
            ]
        )
    story = [Paragraph("Methodology & Limitations", styles["h2"])]
    for line in lines:
        story.append(Paragraph(f"• {_text(line)}", styles["muted"]))
    return story


def _build_pdf(story):
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=LEFT_MARGIN,
        rightMargin=RIGHT_MARGIN,
        topMargin=TOP_MARGIN,
        bottomMargin=BOTTOM_MARGIN,
        title="PhishLens Security Analysis Report",
        author="PhishLens",
    )
    document.build(story, onFirstPage=_add_footer, onLaterPages=_add_footer)
    return buffer.getvalue()


def _url_target(scan):
    return scan.get("normalized_url") or scan.get("target") or "Not present"


def _url_raw_score(scan, indicators, correlations):
    if scan.get("raw_score") is not None:
        return scan["raw_score"]
    total = BASE_SCORE
    total += sum(int(item.get("score_change") or 0) for item in indicators)
    total += sum(int(item.get("score_change") or 0) for item in correlations)
    return total


def _url_coverage_meta(scan, indicators, inspection=None):
    """Return coverage labels for a URL report, including older NULL rows."""
    if inspection and inspection.get("status") == "resolved":
        return "comprehensive", "resolved"
    coverage = (scan.get("analysis_coverage") or "").strip().lower()
    status = (scan.get("destination_status") or "").strip().lower()
    if coverage not in ("full", "limited", "comprehensive"):
        has_shortener = any(
            (item or {}).get("rule_name") == "url_shortener"
            for item in indicators or []
        )
        coverage = "limited" if has_shortener else "full"
    if status not in ("visible", "hidden", "resolved"):
        status = "hidden" if coverage == "limited" else "visible"
    return coverage, status


def _append_destination_inspection(story, styles, inspection):
    """Append stored destination-inspection details. No network calls."""
    heading = Paragraph("Destination Analysis", styles["h2"])
    if not inspection:
        story.append(
            KeepTogether(
                [
                    heading,
                    Paragraph("Not inspected", styles["muted"]),
                ]
            )
        )
        return

    status = (inspection.get("status") or "unknown").strip().lower()
    if status == "resolved":
        block = [
            heading,
            Paragraph("Status: Completed", styles["body"]),
        ]
        if inspection.get("submitted_url"):
            block.append(Paragraph("Submitted URL", styles["label"]))
            block.append(_url_paragraph(styles, inspection.get("submitted_url")))
        block.extend(
            [
                Paragraph("Final Destination", styles["label"]),
                _url_paragraph(styles, inspection.get("final_url")),
                Paragraph(
                    f"Redirect Count: {_text(inspection.get('redirect_count') or 0)}",
                    styles["body"],
                ),
                Paragraph(
                    f"Final Destination Risk: {_text(inspection.get('final_risk_score'))}/100 — "
                    f"{_text(inspection.get('final_classification'))}",
                    styles["body"],
                ),
            ]
        )
        story.append(KeepTogether(block))

        hops = inspection.get("hops") or []
        if hops:
            story.append(Paragraph("Redirect Chain", styles["h3"]))
            for hop in hops:
                label = hop.get("url_text")
                code = hop.get("http_status")
                line = _soft_break_url(label)
                if code is not None:
                    line = f"{line} (HTTP {_text(code)})"
                story.append(Paragraph(line, styles["value"]))

        final_indicators = inspection.get("final_indicators") or []
        if final_indicators:
            story.append(Paragraph("Final Destination Indicators", styles["h3"]))
            for item in final_indicators:
                story.append(
                    Paragraph(
                        f"{_text(item.get('title'))} "
                        f"({_format_points(item.get('score_change'))})",
                        styles["body"],
                    )
                )
        story.append(
            Paragraph(
                "PhishLens resolved the redirect destination and performed "
                "structural URL analysis. This does not guarantee that the "
                "destination is safe or malicious.",
                styles["muted"],
            )
        )
        return

    if status == "blocked":
        story.append(
            KeepTogether(
                [
                    heading,
                    Paragraph("Status: BLOCKED", styles["body"]),
                    Paragraph(
                        "Inspection blocked for security reasons.",
                        styles["body"],
                    ),
                    Paragraph(
                        _text(
                            inspection.get("reason"),
                            "The destination was blocked by PhishLens network safety checks.",
                        ),
                        styles["muted"],
                    ),
                    Paragraph(
                        "A blocked destination is a safety control for PhishLens. "
                        "It is not automatically treated as phishing.",
                        styles["muted"],
                    ),
                ]
            )
        )
        return

    story.append(
        KeepTogether(
            [
                heading,
                Paragraph("Status: FAILED", styles["body"]),
                Paragraph(
                    _text(
                        inspection.get("reason"),
                        "Destination inspection could not be completed.",
                    ),
                    styles["muted"],
                ),
            ]
        )
    )


def _append_page_inspection(story, styles, inspection):
    """Append stored static page-inspection details. No network calls."""
    block = [Paragraph("Static Page Content Analysis", styles["h2"])]
    if not inspection:
        block.append(Paragraph("Not inspected", styles["muted"]))
        story.append(KeepTogether(block))
        return

    status = (inspection.get("status") or "unknown").replace("_", " ").title()
    block.append(Paragraph(f"Status: {_text(status)}", styles["body"]))
    if inspection.get("reason"):
        block.append(
            Paragraph(f"Reason: {_text(inspection.get('reason'))}", styles["muted"])
        )

    if inspection.get("status") != "completed":
        story.append(KeepTogether(block))
        return

    block.extend(
        [
            Paragraph("Page Title", styles["label"]),
            Paragraph(
                _text(inspection.get("page_title"), "(No title)"),
                styles["value"],
            ),
            Paragraph(
                f"Page Risk Score: {_text(inspection.get('risk_score'))} / 100",
                styles["body"],
            ),
            Paragraph(
                f"Classification: {_text(inspection.get('classification'))}",
                styles["body"],
            ),
        ]
    )
    story.append(KeepTogether(block))

    page_indicators = inspection.get("indicators") or []
    if page_indicators:
        story.append(Paragraph("Indicators", styles["h3"]))
        for item in page_indicators:
            story.append(_indicator_block(styles, item, include_severity=False))

    page_correlations = inspection.get("correlations") or []
    if page_correlations:
        story.append(Paragraph("Correlations", styles["h3"]))
        for item in page_correlations:
            story.append(
                Paragraph(
                    f"{_text(item.get('title'))} "
                    f"({_format_points(item.get('score_change'))})",
                    styles["body"],
                )
            )

    story.append(
        Paragraph(
            "Page content was inspected statically. JavaScript and remote "
            "resources were not executed or loaded.",
            styles["muted"],
        )
    )


def _count_field(check, short_name, long_name):
    if check.get(short_name) is not None:
        return check.get(short_name)
    return check.get(long_name)


def _append_one_reputation(story, styles, title, check):
    block = [Paragraph(title, styles["h3"])]
    if not check:
        block.append(Paragraph("External Reputation: Not checked", styles["muted"]))
        story.append(KeepTogether(block))
        return

    status = (check.get("status") or "").strip().lower()
    block.append(
        Paragraph(
            f"Provider: {_text(check.get('provider'), 'VirusTotal')}",
            styles["body"],
        )
    )
    if check.get("checked_at"):
        block.append(
            Paragraph(f"Checked: {_text(check.get('checked_at'))}", styles["body"])
        )

    if status == "unknown":
        block.append(Paragraph("No existing reputation record.", styles["muted"]))
        story.append(KeepTogether(block))
        return
    if status == "rate_limited":
        block.append(
            Paragraph(
                "Reputation check temporarily unavailable. Provider rate limit reached.",
                styles["muted"],
            )
        )
        story.append(KeepTogether(block))
        return
    if status != "completed":
        block.append(
            Paragraph(
                _text(check.get("message"), "External Reputation: Not checked"),
                styles["muted"],
            )
        )
        story.append(KeepTogether(block))
        return

    block.extend(
        [
            Paragraph(
                f"Malicious classifications: {_text(_count_field(check, 'malicious', 'malicious_count'), '0')}",
                styles["body"],
            ),
            Paragraph(
                f"Suspicious classifications: {_text(_count_field(check, 'suspicious', 'suspicious_count'), '0')}",
                styles["body"],
            ),
            Paragraph(
                f"Harmless classifications: {_text(_count_field(check, 'harmless', 'harmless_count'), '0')}",
                styles["body"],
            ),
            Paragraph(
                f"Undetected: {_text(_count_field(check, 'undetected', 'undetected_count'), '0')}",
                styles["body"],
            ),
        ]
    )
    if check.get("total_engines") is not None:
        block.append(
            Paragraph(
                f"Total engines: {_text(check.get('total_engines'))}",
                styles["body"],
            )
        )
    story.append(KeepTogether(block))


def _append_reputation_checks(story, styles, reputation_checks):
    """Append stored reputation results. Never contacts external providers."""
    story.append(Paragraph("External Reputation", styles["h2"]))
    checks = reputation_checks or {}
    submitted = checks.get("submitted_url")
    final = checks.get("final_url")
    if not submitted and not final:
        story.append(Paragraph("External Reputation: Not checked", styles["muted"]))
        story.append(
            Paragraph(
                "External reputation results reflect provider data available at "
                "the time of the check.",
                styles["muted"],
            )
        )
        return

    _append_one_reputation(story, styles, "Submitted URL Reputation", submitted)
    if final:
        _append_one_reputation(story, styles, "Final Destination Reputation", final)

    story.append(
        Paragraph(
            "External reputation results reflect provider data available at "
            "the time of the check.",
            styles["muted"],
        )
    )
    story.append(
        Paragraph(
            "Reputation results provide external evidence and should be "
            "interpreted together with PhishLens's local analysis. No "
            "detections does not guarantee that a URL is safe.",
            styles["muted"],
        )
    )


def _append_combined_assessment(story, styles, assessment):
    """Append stored combined assessment. No network calls."""
    heading = Paragraph("Overall PhishLens Assessment", styles["h2"])
    if not assessment:
        story.append(
            KeepTogether(
                [
                    heading,
                    Paragraph(
                        "No combined assessment was stored for this scan.",
                        styles["muted"],
                    ),
                ]
            )
        )
        return

    coverage = (
        assessment.get("coverage_label")
        or assessment.get("coverage")
        or "LIMITED"
    )
    score = assessment.get("score")
    score_display = f"{score}/100" if score is not None else "Not present"
    summary_table = _table(
        [
            [
                Paragraph("Combined Score", styles["meta_label"]),
                Paragraph(_text(score_display), styles["meta_value"]),
            ],
            [
                Paragraph("Classification", styles["meta_label"]),
                Paragraph(
                    _text(assessment.get("label"), "Not present").upper(),
                    styles["meta_value"],
                ),
            ],
            [
                Paragraph("Evidence Coverage", styles["meta_label"]),
                Paragraph(_text(str(coverage).upper()), styles["meta_value"]),
            ],
        ],
        [USABLE_WIDTH * 0.32, USABLE_WIDTH * 0.68],
        [
            ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
            ("BOX", (0, 0), (-1, -1), 0.5, LIGHT_BORDER),
            ("LINEBELOW", (0, 0), (-1, -2), 0.25, LIGHT_BORDER),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ],
    )

    block = [heading, summary_table, Spacer(1, 4)]
    if assessment.get("summary"):
        block.append(Paragraph(_text(assessment.get("summary")), styles["body"]))

    reasons = assessment.get("reasons") or []
    block.append(Paragraph("Why this assessment?", styles["h3"]))
    if reasons:
        for reason in reasons:
            block.append(Paragraph(f"• {_text(reason)}", styles["body"]))
    else:
        block.append(
            Paragraph(
                "No major warning reasons were recorded for the completed checks.",
                styles["muted"],
            )
        )

    block.append(Paragraph("Recommendation", styles["h3"]))
    block.append(
        Paragraph(
            _text(
                assessment.get("recommendation"),
                "No recommendation was stored.",
            ),
            styles["body"],
        )
    )
    block.append(
        Paragraph(
            "This assessment is based on the evidence available to PhishLens "
            "and is not a guarantee that a website is safe or malicious.",
            styles["muted"],
        )
    )
    story.append(KeepTogether(block))


def _append_combined_breakdown(story, styles, assessment):
    """Append combined score arithmetic from stored assessment. No network."""
    heading = Paragraph("Combined Assessment Breakdown", styles["h2"])
    breakdown = (assessment or {}).get("breakdown") or {}
    if not breakdown:
        story.append(
            KeepTogether(
                [
                    heading,
                    Paragraph(
                        "No combined assessment breakdown was stored for this scan.",
                        styles["muted"],
                    ),
                ]
            )
        )
        return

    strongest_label = breakdown.get("strongest_layer_label") or breakdown.get(
        "strongest_layer"
    ) or "Strongest completed layer"
    rows = [
        [
            Paragraph(f"Strongest completed layer ({_text(strongest_label)})", styles["body"]),
            Paragraph(_text(breakdown.get("strongest_layer_score"), "0"), styles["body"]),
        ]
    ]
    adjustments = breakdown.get("cross_layer_adjustments") or []
    if adjustments:
        for item in adjustments:
            change = item.get("score_change") or 0
            sign = "+" if change > 0 else ""
            rows.append(
                [
                    Paragraph(_text(item.get("title"), "Correlation"), styles["body"]),
                    Paragraph(f"{sign}{change}", styles["body"]),
                ]
            )
    else:
        rows.append(
            [
                Paragraph("Cross-layer correlation", styles["body"]),
                Paragraph("+0", styles["body"]),
            ]
        )

    vt = breakdown.get("virustotal_adjustment") or 0
    vt_sign = "+" if vt > 0 else ""
    rows.append(
        [
            Paragraph("VirusTotal evidence", styles["body"]),
            Paragraph(f"{vt_sign}{vt}", styles["body"]),
        ]
    )
    final = breakdown.get("final_score")
    if final is None:
        final = (assessment or {}).get("score")
    rows.append(
        [
            Paragraph("Combined score", styles["body"]),
            Paragraph(f"{_text(final)}/100", styles["body"]),
        ]
    )

    block = [
        heading,
        _table(
            rows,
            [USABLE_WIDTH * 0.78, USABLE_WIDTH * 0.22],
            [
                ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
                ("BOX", (0, 0), (-1, -1), 0.5, LIGHT_BORDER),
                ("LINEBELOW", (0, 0), (-1, -2), 0.25, LIGHT_BORDER),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ],
        ),
    ]
    for item in adjustments:
        if item.get("explanation"):
            block.append(Paragraph(_text(item.get("explanation")), styles["muted"]))
    story.append(KeepTogether(block))


def generate_url_report(scan_data):
    """Return PDF bytes for a stored URL scan."""
    styles = _styles()
    scan = scan_data.get("scan") or {}
    indicators = scan_data.get("indicators") or []
    correlations = scan_data.get("correlations") or []
    inspection = scan_data.get("redirect_inspection")
    page_inspection = scan_data.get("page_inspection")
    reputation_checks = scan_data.get("reputation_checks") or {}
    combined_assessment = scan_data.get("combined_assessment")
    # Prefer stored assessment; fill missing score/breakdown offline from layers.
    if combined_assessment is None or combined_assessment.get("score") is None:
        fresh = assess_scan_record(scan_data)
        if combined_assessment is None:
            combined_assessment = fresh
        else:
            combined_assessment = {
                **combined_assessment,
                "score": fresh.get("score"),
                "breakdown": combined_assessment.get("breakdown") or fresh.get("breakdown"),
            }
    elif not combined_assessment.get("breakdown"):
        fresh = assess_scan_record(scan_data)
        combined_assessment = {
            **combined_assessment,
            "breakdown": fresh.get("breakdown"),
        }

    score = scan.get("risk_score")
    classification = scan.get("classification") or "Not present"
    target = _url_target(scan)
    coverage, destination_status = _url_coverage_meta(scan, indicators, inspection)
    base_score = scan.get("base_score")
    if base_score is None:
        base_score = BASE_SCORE
    raw_score = _url_raw_score(scan, indicators, correlations)

    display_label = (combined_assessment or {}).get("label") or classification
    display_score = (combined_assessment or {}).get("score")
    if display_score is None:
        display_score = score
    story = []
    story.extend(_header_block(styles, "URL Analysis", scan, display_score, display_label))
    _append_combined_assessment(story, styles, combined_assessment)

    story.append(Paragraph("Submitted URL Analysis", styles["h2"]))
    story.append(
        Paragraph(
            "PhishLens analyzed the URL text "
            f"<b>{_soft_break_url(target)}</b> and produced a stored submitted-URL risk "
            f"score of <b>{_text(score)}/100</b> ({_text(classification)}). "
            f"The report includes {_text(len(indicators))} indicator"
            f"{'' if len(indicators) == 1 else 's'} and "
            f"{_text(len(correlations))} correlation factor"
            f"{'' if len(correlations) == 1 else 's'}. "
            "Layer scores are not summed into the combined assessment; the "
            "overall score uses the strongest completed layer plus explicit "
            "cross-layer and reputation adjustments.",
            styles["body"],
        )
    )
    if classification == "Low Risk":
        story.append(
            Paragraph(
                "Few suspicious URL characteristics were recorded for this scan. "
                "This does not guarantee that the destination is safe.",
                styles["muted"],
            )
        )

    story.append(
        KeepTogether(
            [
                Paragraph("Analyzed URL", styles["h2"]),
                _url_paragraph(styles, target),
            ]
        )
    )

    coverage_block = [
        Paragraph("Analysis Coverage", styles["h2"]),
        Paragraph(
            f"Analysis Coverage: {_text(coverage.capitalize())}",
            styles["body"],
        ),
        Paragraph(
            f"Destination Status: {_text(destination_status.capitalize())}",
            styles["body"],
        ),
    ]
    if destination_status == "hidden":
        coverage_block.extend(
            [
                Paragraph(
                    "The final destination was not inspected.",
                    styles["muted"],
                ),
                Paragraph(
                    "The risk score does not represent the unseen final destination.",
                    styles["muted"],
                ),
            ]
        )
    story.append(KeepTogether(coverage_block))

    _append_destination_inspection(story, styles, inspection)
    _append_page_inspection(story, styles, page_inspection)
    _append_reputation_checks(story, styles, reputation_checks)

    _append_combined_breakdown(story, styles, combined_assessment)

    story.append(
        KeepTogether(
            [
                Paragraph("Recommendation", styles["h2"]),
                Paragraph(
                    _text(
                        (combined_assessment or {}).get("recommendation")
                        or scan.get("recommendation"),
                        "No recommendation was stored.",
                    ),
                    styles["body"],
                ),
            ]
        )
    )

    story.append(Paragraph("Submitted URL Score Breakdown", styles["h2"]))
    story.append(
        _breakdown_table(
            styles,
            base_score,
            indicators,
            correlations,
            raw_score,
            score,
        )
    )

    story.append(Paragraph("Detected Indicators", styles["h2"]))
    if indicators:
        for item in indicators:
            story.append(_indicator_block(styles, item, include_severity=False))
    else:
        story.append(Paragraph("None detected", styles["muted"]))

    story.append(Paragraph("Correlation Factors", styles["h2"]))
    story.append(
        Paragraph(
            "Correlation factors represent combinations of indicators that "
            "increase the heuristic score when they appear together.",
            styles["muted"],
        )
    )
    if correlations:
        for item in correlations:
            story.append(_indicator_block(styles, item, include_severity=False))
    else:
        story.append(Paragraph("None detected", styles["muted"]))

    story.extend(_methodology(styles, "url"))
    return _build_pdf(story)


def generate_email_report(scan_data):
    """Return PDF bytes for a stored Email scan."""
    styles = _styles()
    scan = scan_data.get("scan") or {}
    indicators = scan_data.get("indicators") or []
    correlations = scan_data.get("correlations") or []
    links = scan_data.get("email_links") or []
    attachments = scan_data.get("email_attachments") or []
    score = scan.get("risk_score")
    classification = scan.get("classification") or "Not present"
    subject = scan.get("email_subject") or scan.get("target") or "(No subject)"
    base_score = scan.get("base_score")
    if base_score is None:
        base_score = 10
    raw_score = scan.get("raw_score")
    if raw_score is None:
        raw_score = base_score
        raw_score += sum(int(item.get("score_change") or 0) for item in indicators)
        raw_score += sum(int(item.get("score_change") or 0) for item in correlations)

    suspicious_links = sum(
        1
        for item in links
        if item.get("classification") in ("Suspicious", "High Risk")
    )

    story = []
    story.extend(_header_block(styles, "Email Analysis", scan, score, classification))
    story.append(Paragraph("Executive Summary", styles["h2"]))
    story.append(
        Paragraph(
            "PhishLens analyzed a stored email summary for subject "
            f"<b>{_text(subject)}</b> and produced a risk score of "
            f"<b>{_text(score)}/100</b> ({_text(classification)}). "
            f"The report includes {_text(len(indicators))} indicator"
            f"{'' if len(indicators) == 1 else 's'}, "
            f"{_text(len(correlations))} correlation factor"
            f"{'' if len(correlations) == 1 else 's'}, and "
            f"{_text(suspicious_links)} suspicious embedded link"
            f"{'' if suspicious_links == 1 else 's'}. "
            "PhishLens identified characteristics associated with elevated risk "
            "only when those indicators were present.",
            styles["body"],
        )
    )

    story.append(Paragraph("Stored Email Metadata", styles["h2"]))
    story.append(
        Paragraph(
            "PhishLens does not retain the complete email body or attachment "
            "contents in historical analysis records.",
            styles["muted"],
        )
    )
    story.append(
        _kv_table(
            styles,
            [
                ("From", scan.get("email_from")),
                ("To", scan.get("email_to")),
                ("Subject", subject),
                ("Email Date", scan.get("email_date")),
            ],
        )
    )

    story.append(
        KeepTogether(
            [
                Paragraph("Recommendation", styles["h2"]),
                Paragraph(
                    _text(scan.get("recommendation"), "No recommendation was stored."),
                    styles["body"],
                ),
            ]
        )
    )

    story.append(Paragraph("Score Breakdown", styles["h2"]))
    story.append(
        _breakdown_table(
            styles,
            base_score,
            indicators,
            correlations,
            raw_score,
            score,
        )
    )

    story.append(Paragraph("Security Indicators", styles["h2"]))
    if indicators:
        for item in indicators:
            story.append(_indicator_block(styles, item, include_severity=True))
    else:
        story.append(Paragraph("None detected", styles["muted"]))

    story.append(Paragraph("Correlation Factors", styles["h2"]))
    story.append(
        Paragraph(
            "Correlation factors represent combinations of indicators that "
            "increase the heuristic score when they appear together.",
            styles["muted"],
        )
    )
    if correlations:
        for item in correlations:
            story.append(_indicator_block(styles, item, include_severity=False))
    else:
        story.append(Paragraph("None detected", styles["muted"]))

    story.append(Paragraph("Embedded Link Analysis", styles["h2"]))
    story.append(
        Paragraph(
            "Local URL Risk Scores below are separate from the Email Risk Score. "
            "URLs are shown as plain text and are not clickable.",
            styles["muted"],
        )
    )
    if links:
        for item in links:
            block = [
                Paragraph("Embedded Link", styles["label"]),
                _url_paragraph(styles, item.get("url_text")),
                Paragraph(
                    f"Local URL Risk Score: {_text(item.get('risk_score'))} / 100",
                    styles["body"],
                ),
                Paragraph(
                    f"Classification: {_text(item.get('classification'))}",
                    styles["body"],
                ),
            ]
            summary = item.get("indicator_summary")
            if summary:
                block.append(Paragraph("Detected URL Indicators", styles["label"]))
                for line in str(summary).splitlines():
                    if line.strip():
                        block.append(
                            Paragraph(f"• {_text(line.strip())}", styles["muted"])
                        )
            story.append(KeepTogether(block))
            story.append(Spacer(1, 4))
    else:
        story.append(Paragraph("None detected", styles["muted"]))

    story.append(Paragraph("Attachments", styles["h2"]))
    story.append(Paragraph("Attachment contents are not stored.", styles["muted"]))
    if attachments:
        for item in attachments:
            size = item.get("size")
            if size is None:
                size_text = "Not present"
            elif size < 1024:
                size_text = f"{size} bytes"
            else:
                size_text = f"{size / 1024:.1f} KB"
            story.append(
                Paragraph(
                    f"Filename: {_text(item.get('filename'))} · "
                    f"Content Type: {_text(item.get('content_type'))} · "
                    f"Size: {_text(size_text)}",
                    styles["body"],
                )
            )
    else:
        story.append(Paragraph("None detected", styles["muted"]))

    story.extend(_methodology(styles, "email"))
    return _build_pdf(story)
