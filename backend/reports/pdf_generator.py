import datetime
import io
import html
from typing import Dict, Any, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether
)


def escape_pdf_text(text: Any) -> str:
    """Escape special XML/HTML entities for ReportLab Paragraphs."""
    if text is None:
        return ""
    s = str(text)
    return html.escape(s).replace("\n", "<br/>")


def generate_pdf_report(analysis_data: Dict[str, Any]) -> io.BytesIO:
    """
    Generate an authentic, professional PDF inspection report using ReportLab.
    Outputs a BytesIO stream containing the generated PDF binary.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0A192F"),
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#4A5568"),
        spaceAfter=15
    )

    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=12,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1F2937")
    )

    code_style = ParagraphStyle(
        "CodeSnippet",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0F172A"),
        backColor=colors.HexColor("#F1F5F9")
    )

    disclaimer_style = ParagraphStyle(
        "Disclaimer",
        parent=styles["Italic"],
        fontName="Helvetica-Oblique",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#64748B")
    )

    elements = []

    # Title & Metadata
    elements.append(Paragraph("Smart Code Inspection Platform", title_style))
    elements.append(Paragraph("Security Vulnerability Assessment & Compliance Report", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284C7"), spaceAfter=12))

    filename = analysis_data.get("filename", "untitled")
    language = str(analysis_data.get("language", "unknown")).capitalize()
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    valid_syntax = "Valid (Passed)" if analysis_data.get("valid_syntax") else "Invalid / Compile Errors"

    meta_table_data = [
        [
            Paragraph("<b>Target File:</b> " + escape_pdf_text(filename), body_style),
            Paragraph("<b>Language:</b> " + escape_pdf_text(language), body_style)
        ],
        [
            Paragraph("<b>Inspection Date:</b> " + escape_pdf_text(now_str), body_style),
            Paragraph("<b>Syntax / Compiler:</b> " + escape_pdf_text(valid_syntax), body_style)
        ]
    ]

    meta_table = Table(meta_table_data, colWidths=[260, 270])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 14))

    # Summary Statistics
    summary = analysis_data.get("summary", {})
    total = summary.get("total_findings", 0)
    crit = summary.get("critical", 0)
    high = summary.get("high", 0)
    med = summary.get("medium", 0)
    low = summary.get("low", 0)

    elements.append(Paragraph("Executive Vulnerability Summary", section_heading))

    summary_table_data = [
        ["Total Findings", "Critical", "High", "Medium", "Low / Info"],
        [str(total), str(crit), str(high), str(med), str(low)]
    ]

    summary_table = Table(summary_table_data, colWidths=[106, 106, 106, 106, 106])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#FFFFFF")),
        ("TEXTCOLOR", (1, 1), (1, 1), colors.HexColor("#DC2626")),
        ("TEXTCOLOR", (2, 1), (2, 1), colors.HexColor("#EA580C")),
        ("TEXTCOLOR", (3, 1), (3, 1), colors.HexColor("#D97706")),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, 1), 12),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 14))

    # Detailed Findings
    findings: List[Dict[str, Any]] = analysis_data.get("findings", [])
    elements.append(Paragraph(f"Detailed Security Findings ({len(findings)})", section_heading))

    if not findings:
        elements.append(Paragraph("No security vulnerabilities detected by deterministic rulebook inspection.", body_style))
        elements.append(Spacer(1, 10))
    else:
        for idx, f in enumerate(findings, start=1):
            sev = f.get("severity", "Medium")
            sev_color = "#DC2626" if sev == "Critical" else ("#EA580C" if sev == "High" else "#D97706")
            rule_id = f.get("rule_id", "SEC")
            title = f.get("title", "Finding")
            line_no = f.get("line", 1)
            evidence = f.get("evidence", "")
            risk = f.get("risk_explanation", "")
            mitigation = f.get("mitigation", "")
            owasp_urls = f.get("owasp_references", [])

            urls_html = "<br/>".join([f"&bull; <a href='{escape_pdf_text(u)}'>{escape_pdf_text(u)}</a>" for u in owasp_urls]) if owasp_urls else "None"

            finding_rows = [
                [
                    Paragraph(f"<b>#{idx}. {escape_pdf_text(title)}</b> [{escape_pdf_text(rule_id)}]", body_style),
                    Paragraph(f"<font color='{sev_color}'><b>{escape_pdf_text(sev.upper())}</b></font> (Line {line_no})", body_style)
                ],
                [
                    Paragraph("<b>Evidence:</b>", body_style),
                    Paragraph(f"<font face='Courier'>{escape_pdf_text(evidence)}</font>", code_style)
                ],
                [
                    Paragraph("<b>Risk:</b>", body_style),
                    Paragraph(escape_pdf_text(risk), body_style)
                ],
                [
                    Paragraph("<b>Mitigation:</b>", body_style),
                    Paragraph(escape_pdf_text(mitigation), body_style)
                ],
                [
                    Paragraph("<b>OWASP Sources:</b>", body_style),
                    Paragraph(urls_html, body_style)
                ]
            ]

            card_table = Table(finding_rows, colWidths=[110, 420])
            card_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("PADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))

            elements.append(KeepTogether([card_table, Spacer(1, 10)]))

    # Optional AI Explanations Section
    ai_explanation = analysis_data.get("ai_explanation")
    if ai_explanation and isinstance(ai_explanation, dict) and ai_explanation.get("explanation"):
        elements.append(Spacer(1, 8))
        elements.append(Paragraph("AI-Generated Advisory Remediation", section_heading))
        ai_text = ai_explanation.get("explanation", "")
        elements.append(Paragraph(
            "<i>Note: The following commentary was generated by an AI assistant for educational and advisory reference.</i>",
            disclaimer_style
        ))
        elements.append(Spacer(1, 4))
        elements.append(Paragraph(escape_pdf_text(ai_text), body_style))
        elements.append(Spacer(1, 10))

    # Disclaimer & Limitations
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94A3B8"), spaceAfter=8))
    elements.append(Paragraph("<b>Analysis Scope & Limitations:</b>", disclaimer_style))
    elements.append(Paragraph(
        "This automated inspection report is generated through deterministic static AST/lexical rules and compiler validation. "
        "Static pattern analysis may produce false positives or false negatives and does not guarantee the complete absence of vulnerabilities. "
        "Always combine automated code review with comprehensive security architecture reviews, threat modeling, and manual penetration testing.",
        disclaimer_style
    ))

    doc.build(elements)
    buffer.seek(0)
    return buffer
