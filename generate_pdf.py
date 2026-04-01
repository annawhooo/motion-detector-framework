#!/usr/bin/env python3
"""Convert the Motion Detector Framework markdown to a professional PDF."""

import re
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle,
    KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from pathlib import Path


def parse_markdown(md_text: str) -> list:
    """Parse markdown into a list of styled elements."""
    elements = []
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        'PaperTitle', parent=styles['Title'],
        fontSize=18, spaceAfter=6, alignment=TA_CENTER,
        fontName='Times-Bold'
    ))
    styles.add(ParagraphStyle(
        'Subtitle', parent=styles['Normal'],
        fontSize=12, spaceAfter=4, alignment=TA_CENTER,
        fontName='Times-Italic', textColor=HexColor('#444444')
    ))
    styles.add(ParagraphStyle(
        'Author', parent=styles['Normal'],
        fontSize=11, spaceAfter=12, alignment=TA_CENTER,
        fontName='Times-Roman'
    ))
    styles.add(ParagraphStyle(
        'SectionHead', parent=styles['Heading1'],
        fontSize=14, spaceBefore=18, spaceAfter=8,
        fontName='Times-Bold', textColor=HexColor('#1a1a1a')
    ))
    styles.add(ParagraphStyle(
        'SubsectionHead', parent=styles['Heading2'],
        fontSize=12, spaceBefore=14, spaceAfter=6,
        fontName='Times-Bold', textColor=HexColor('#333333')
    ))
    styles.add(ParagraphStyle(
        'SubsubHead', parent=styles['Heading3'],
        fontSize=11, spaceBefore=10, spaceAfter=4,
        fontName='Times-Bold', textColor=HexColor('#444444')
    ))
    styles.add(ParagraphStyle(
        'BodyText2', parent=styles['Normal'],
        fontSize=10, spaceAfter=6, alignment=TA_JUSTIFY,
        fontName='Times-Roman', leading=14
    ))
    styles.add(ParagraphStyle(
        'BulletItem', parent=styles['Normal'],
        fontSize=10, spaceAfter=3, leftIndent=24, bulletIndent=12,
        fontName='Times-Roman', leading=13
    ))
    styles.add(ParagraphStyle(
        'RuleItem', parent=styles['Normal'],
        fontSize=9, spaceAfter=2, leftIndent=24,
        fontName='Times-Roman', leading=12
    ))
    styles.add(ParagraphStyle(
        'RefStyle', parent=styles['Normal'],
        fontSize=9, spaceAfter=4, leftIndent=18, firstLineIndent=-18,
        fontName='Times-Roman', leading=12
    ))

    def md_to_para(text: str) -> str:
        text = re.sub(r'\*\*\*(.+?)\*\*\*', r'<b><i>\1</i></b>', text)
        text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
        text = re.sub(r'\*(.+?)\*', r'<i>\1</i>', text)
        text = re.sub(r'`(.+?)`', r'<font face="Courier" size="9">\1</font>', text)
        text = re.sub(r'\[(.+?)\]\((.+?)\)', r'<link href="\2">\1</link>', text)
        return text

    lines = md_text.split('\n')
    i = 0
    in_table = False
    table_rows = []

    while i < len(lines):
        line = lines[i].rstrip()

        if line.strip() == '---':
            i += 1
            continue
        if line.startswith('# ') and not line.startswith('## '):
            title = line[2:].strip()
            elements.append(Spacer(1, 0.3 * inch))
            elements.append(Paragraph(md_to_para(title), styles['PaperTitle']))
            i += 1
            continue
        if line.startswith('**Behavioral Diagnostics'):
            elements.append(Paragraph(md_to_para(line.replace('**', '')), styles['Subtitle']))
            i += 1
            continue
        if line.startswith('*Anna Hix'):
            elements.append(Paragraph(line.replace('*', ''), styles['Author']))
            elements.append(Spacer(1, 0.2 * inch))
            i += 1
            continue
        if line.startswith('### '):
            header = line[4:].strip()
            elements.append(Paragraph(md_to_para(header), styles['SubsubHead']))
            i += 1
            continue
        if line.startswith('## '):
            header = line[3:].strip()
            elements.append(Paragraph(md_to_para(header), styles['SectionHead']))
            i += 1
            continue

        if '|' in line and line.strip().startswith('|'):
            if not in_table:
                in_table = True
                table_rows = []
            cells = [c.strip() for c in line.split('|')[1:-1]]
            if all(set(c) <= set('-: ') for c in cells):
                i += 1
                continue
            table_rows.append(cells)
            i += 1
            if i < len(lines) and '|' in lines[i] and lines[i].strip().startswith('|'):
                continue
            else:
                in_table = False
                if table_rows:
                    formatted_rows = []
                    for row in table_rows:
                        formatted_row = []
                        for cell in row:
                            cell_text = md_to_para(cell)
                            formatted_row.append(
                                Paragraph(cell_text, ParagraphStyle(
                                    'TableCell', parent=styles['Normal'],
                                    fontSize=8, fontName='Times-Roman', leading=10
                                ))
                            )
                        formatted_rows.append(formatted_row)
                    if formatted_rows:
                        num_cols = max(len(r) for r in formatted_rows)
                        for row in formatted_rows:
                            while len(row) < num_cols:
                                row.append(Paragraph('', styles['Normal']))
                        col_width = (6.5 * inch) / num_cols
                        t = Table(formatted_rows, colWidths=[col_width] * num_cols)
                        t.setStyle(TableStyle([
                            ('FONTNAME', (0, 0), (-1, 0), 'Times-Bold'),
                            ('FONTSIZE', (0, 0), (-1, -1), 8),
                            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#e8e8e8')),
                            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
                            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                            ('TOPPADDING', (0, 0), (-1, -1), 4),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                            ('LEFTPADDING', (0, 0), (-1, -1), 6),
                            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                        ]))
                        elements.append(Spacer(1, 6))
                        elements.append(t)
                        elements.append(Spacer(1, 6))
                continue

        ref_match = re.match(r'^(\d+)\.\s+(.+)', line)
        if ref_match and i > 200:
            num = ref_match.group(1)
            text = ref_match.group(2)
            while i + 1 < len(lines) and lines[i + 1].strip() and not lines[i + 1].strip().startswith(('##', '-', '|')) and not re.match(r'^\d+\.', lines[i + 1].strip()):
                i += 1
                text += ' ' + lines[i].strip()
            elements.append(Paragraph(f"[{num}] {md_to_para(text)}", styles['RefStyle']))
            i += 1
            continue

        if line.strip().startswith('- ') or line.strip().startswith('* '):
            text = line.strip()[2:]
            while i + 1 < len(lines) and lines[i + 1].strip() and not lines[i + 1].strip().startswith(('-', '*', '#', '|', '##')) and not re.match(r'^\d+\.', lines[i + 1].strip()):
                i += 1
                text += ' ' + lines[i].strip()
            elements.append(Paragraph(f"\u2022 {md_to_para(text)}", styles['BulletItem']))
            i += 1
            continue

        rule_match = re.match(r'^- \*\*(.+?):\*\*\s*(.+)', line.strip())
        if rule_match:
            label = rule_match.group(1)
            value = rule_match.group(2)
            elements.append(Paragraph(
                f"<b>{label}:</b> {md_to_para(value)}", styles['RuleItem']
            ))
            i += 1
            continue

        if line.strip():
            para_text = line.strip()
            while i + 1 < len(lines) and lines[i + 1].strip() and not lines[i + 1].strip().startswith(('#', '-', '*', '|', '---')) and not re.match(r'^\d+\.', lines[i + 1].strip()):
                i += 1
                para_text += ' ' + lines[i].strip()
            elements.append(Paragraph(md_to_para(para_text), styles['BodyText2']))
            i += 1
            continue

        i += 1

    return elements


def build_pdf(md_path: str, output_path: str):
    """Build PDF from markdown file."""
    md_text = Path(md_path).read_text(encoding='utf-8')
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        leftMargin=1 * inch,
        rightMargin=1 * inch,
        title="The Motion Detector Framework",
        author="Anna Hix",
    )
    elements = parse_markdown(md_text)
    doc.build(elements)
    print(f"PDF generated: {output_path}")


if __name__ == "__main__":
    import sys
    base = Path(sys.argv[0]).parent
    build_pdf(
        str(base / "paper" / "motion-detector-framework.md"),
        str(base / "paper" / "motion-detector-framework.pdf"),
    )
