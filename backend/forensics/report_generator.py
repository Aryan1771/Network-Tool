import json
from pathlib import Path
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas
from backend.config import Config
from backend.database.db import query_db, execute_db
from backend.forensics.hasher import ForensicHasher
from backend.forensics.chain_of_custody import ChainOfCustodyService

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to calculate total page count for professional headers/footers.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 750, "NETWORK INCIDENT INVESTIGATION & DIGITAL FORENSIC REPORT")
            self.drawRightString(612 - 54, 750, "CONFIDENTIAL / ACADEMIC LAB (JIIT 24B15CS313)")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 742, 612 - 54, 742)

        # Footer (all pages)
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 45, 612 - 54, 45)
        self.drawString(54, 32, "JIIT Computer Networks Lab (24B15CS313) - Automated Forensic System")
        self.drawRightString(612 - 54, 32, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


class ForensicReportGenerator:
    """
    Generates courtroom/audit-ready PDF forensic investigation reports.
    """

    @staticmethod
    def generate_report_id():
        row = query_db("SELECT COUNT(*) as count FROM forensic_reports", one=True)
        count = (row["count"] if row else 0) + 1
        year = datetime.now().year
        return f"REP-{year}-{count:04d}"

    @classmethod
    def create_report_for_incident(cls, incident_id, generated_by="Forensic Examiner (Team JIIT)"):
        """
        Gathers all related incident data, evidence hashes, timeline, chain-of-custody,
        and generates a downloadable PDF forensic report.
        """
        # Fetch Incident Details
        inc = query_db("SELECT * FROM incidents WHERE id = ?", (incident_id,), one=True)
        if not inc:
            raise ValueError(f"Incident ID {incident_id} not found")

        # Fetch Linked Evidence
        evd = query_db("SELECT * FROM evidence WHERE incident_id = ? OR session_id = ? ORDER BY id DESC LIMIT 1",
                       (incident_id, inc.get("session_id")), one=True)

        # Fetch Timeline Events
        events = query_db("SELECT * FROM incident_events WHERE incident_id = ? ORDER BY timestamp ASC",
                          (incident_id,))

        # Fetch Chain of Custody for evidence if available
        custody_rows = []
        if evd:
            custody_rows = query_db("SELECT * FROM chain_of_custody WHERE evidence_id = ? ORDER BY id ASC",
                                    (evd["id"],))

        # Fetch Analyst Notes
        notes = query_db("SELECT * FROM investigation_notes WHERE incident_id = ? ORDER BY created_at ASC",
                         (incident_id,))

        report_id = cls.generate_report_id()
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"Forensic_Report_{report_id}_{incident_id}_{timestamp_str}.pdf"
        output_path = Path(Config.REPORTS_PATH) / filename

        # Build PDF with ReportLab
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54
        )

        styles = getSampleStyleSheet()
        # Custom styles
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold",
            spaceAfter=4
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#059669"),
            fontName="Helvetica-Bold",
            spaceAfter=15
        )
        h2_style = ParagraphStyle(
            "Heading2Custom",
            parent=styles["Heading2"],
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#1e293b"),
            fontName="Helvetica-Bold",
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            "BodyCustom",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155"),
            fontName="Helvetica"
        )
        body_bold = ParagraphStyle(
            "BodyBold",
            parent=body_style,
            fontName="Helvetica-Bold"
        )
        code_style = ParagraphStyle(
            "CodeCustom",
            parent=styles["Code"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0f172a"),
            fontName="Courier"
        )

        story = []

        # Header Block
        story.append(Paragraph("DIGITAL FORENSIC INVESTIGATION REPORT", title_style))
        story.append(Paragraph("JAYPEE INSTITUTE OF INFORMATION TECHNOLOGY — COMPUTER NETWORKS LAB (24B15CS313)", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#10b981"), spaceAfter=12))

        # Meta Summary Table
        meta_data = [
            [Paragraph("<b>Report ID:</b>", body_style), Paragraph(report_id, body_style),
             Paragraph("<b>Generated Date:</b>", body_style), Paragraph(datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"), body_style)],
            [Paragraph("<b>Incident ID:</b>", body_style), Paragraph(inc["id"], body_style),
             Paragraph("<b>Classification:</b>", body_style), Paragraph(inc["incident_type"], body_bold)],
            [Paragraph("<b>Severity:</b>", body_style), Paragraph(f"<b>{inc['severity']}</b>", body_style),
             Paragraph("<b>Investigation Status:</b>", body_style), Paragraph(inc["status"], body_bold)],
            [Paragraph("<b>Lead Examiner:</b>", body_style), Paragraph(generated_by, body_style),
             Paragraph("<b>Assigned System:</b>", body_style), Paragraph(inc.get("analyst_assignee", "Forensic Engine"), body_style)],
        ]
        t_meta = Table(meta_data, colWidths=[100, 150, 110, 144])
        t_meta.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_meta)
        story.append(Spacer(1, 12))

        # Executive Summary
        story.append(Paragraph("1. Executive Incident Summary", h2_style))
        summary_text = (
            f"On <b>{inc['detected_at']}</b>, the automated forensic analysis engine detected anomalous network activity "
            f"classified as <b>{inc['incident_type']}</b> ({inc['severity']} Severity). "
            f"The primary source host was identified as <b>{inc['src_ip']}</b> directing traffic towards target "
            f"<b>{inc['dst_ip']}</b> across protocol <b>{inc['protocol']}</b>. "
            f"{inc['description']}"
        )
        story.append(Paragraph(summary_text, body_style))
        story.append(Spacer(1, 10))

        # Technical Parameters & Threshold Rules
        story.append(Paragraph("2. Technical Attributes and Detection Rule", h2_style))
        tech_data = [
            [Paragraph("<b>Source IP Address</b>", body_style), Paragraph(inc["src_ip"], body_style)],
            [Paragraph("<b>Destination IP Address</b>", body_style), Paragraph(inc["dst_ip"], body_style)],
            [Paragraph("<b>Target Port(s)</b>", body_style), Paragraph(str(inc.get("target_ports") or "Multiple"), body_style)],
            [Paragraph("<b>Transport Protocol</b>", body_style), Paragraph(inc["protocol"], body_style)],
            [Paragraph("<b>Rule Identifier</b>", body_style), Paragraph(inc["rule_name"], body_style)],
            [Paragraph("<b>Threshold Configuration</b>", body_style), Paragraph(inc.get("threshold_details") or "N/A", code_style)],
        ]
        t_tech = Table(tech_data, colWidths=[160, 344])
        t_tech.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_tech)
        story.append(Spacer(1, 10))

        # Digital Evidence Preservation & Cryptographic Hash
        story.append(Paragraph("3. Digital Evidence Preservation & Cryptographic Hash", h2_style))
        if evd:
            evd_data = [
                [Paragraph("<b>Evidence ID</b>", body_style), Paragraph(evd["id"], body_style)],
                [Paragraph("<b>Original Capture File</b>", body_style), Paragraph(evd["original_filename"], body_style)],
                [Paragraph("<b>Vault Stored Filename</b>", body_style), Paragraph(evd["stored_filename"], body_style)],
                [Paragraph("<b>File Size</b>", body_style), Paragraph(f"{evd['file_size_bytes']:,} bytes", body_style)],
                [Paragraph("<b>SHA-256 Hash</b>", body_style), Paragraph(f"<b>{evd['sha256_hash']}</b>", code_style)],
                [Paragraph("<b>Integrity Status</b>", body_style), Paragraph(f"<b>{evd['verification_status']}</b>", body_style)],
                [Paragraph("<b>Storage Location</b>", body_style), Paragraph(evd["file_path"], code_style)],
            ]
            t_evd = Table(evd_data, colWidths=[150, 354])
            t_evd.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(t_evd)
        else:
            story.append(Paragraph("<i>No physical PCAP evidence file linked to this incident session.</i>", body_style))
        story.append(Spacer(1, 10))

        # Incident Investigation Timeline
        story.append(Paragraph("4. Correlated Incident Timeline", h2_style))
        if events:
            time_table_data = [[
                Paragraph("<b>Timestamp</b>", body_bold),
                Paragraph("<b>Event Milestone</b>", body_bold),
                Paragraph("<b>Severity</b>", body_bold),
                Paragraph("<b>Milestone Details</b>", body_bold)
            ]]
            for ev in events:
                time_table_data.append([
                    Paragraph(ev["datetime_str"], body_style),
                    Paragraph(ev["event_type"], body_style),
                    Paragraph(ev.get("severity") or "INFO", body_style),
                    Paragraph(f"<b>{ev['summary']}</b><br/>{ev.get('details') or ''}", body_style)
                ])
            t_time = Table(time_table_data, colWidths=[110, 110, 60, 224])
            t_time.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(t_time)
        else:
            story.append(Paragraph("<i>No timeline events logged.</i>", body_style))
        story.append(Spacer(1, 10))

        # Chain of Custody History
        story.append(Paragraph("5. Chain-of-Custody Audit Trail (ISO/IEC 27037)", h2_style))
        if custody_rows:
            coc_table_data = [[
                Paragraph("<b>Log ID</b>", body_bold),
                Paragraph("<b>Timestamp</b>", body_bold),
                Paragraph("<b>Action</b>", body_bold),
                Paragraph("<b>Actor (Role)</b>", body_bold),
                Paragraph("<b>Result</b>", body_bold)
            ]]
            for c in custody_rows:
                coc_table_data.append([
                    Paragraph(c["log_id"], code_style),
                    Paragraph(str(c["timestamp"]), body_style),
                    Paragraph(c["action"], body_style),
                    Paragraph(f"{c['actor']} ({c['actor_role']})", body_style),
                    Paragraph(c.get("verification_result") or "LOGGED", body_style)
                ])
            t_coc = Table(coc_table_data, colWidths=[80, 100, 120, 130, 74])
            t_coc.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            story.append(t_coc)
        else:
            story.append(Paragraph("<i>No custody logs recorded for this evidence item.</i>", body_style))
        story.append(Spacer(1, 10))

        # Examiner Notes & Signatures
        story.append(Paragraph("6. Forensic Notes & Attestation", h2_style))
        if notes:
            for n in notes:
                story.append(Paragraph(f"<b>[{n['created_at']}] {n['author']}:</b> {n['note_text']}", body_style))
                story.append(Spacer(1, 4))
        else:
            story.append(Paragraph("<i>No manual analyst annotations appended. Analysis validated automatically.</i>", body_style))

        story.append(Spacer(1, 15))
        sig_data = [
            [Paragraph("<b>Forensic Analyst Signature:</b>", body_style), Paragraph("<b>Laboratory Supervisor Sign-off:</b>", body_style)],
            [Paragraph("<br/><br/>__________________________________<br/>Team JIIT Forensic Lead", body_style),
             Paragraph("<br/><br/>__________________________________<br/>JIIT Computer Networks Department", body_style)]
        ]
        t_sig = Table(sig_data, colWidths=[252, 252])
        t_sig.setStyle(TableStyle([
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(KeepTogether([t_sig]))

        # Build Document
        doc.build(story, canvasmaker=NumberedCanvas)

        # Compute Report Hash & Record into Database
        report_hash = ForensicHasher.calculate_file_sha256(output_path)
        report_size = output_path.stat().st_size

        execute_db("""
            INSERT INTO forensic_reports (
                id, incident_id, evidence_id, report_title, generated_by,
                file_path, file_size_bytes, sha256_hash, summary, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report_id, incident_id, evd["id"] if evd else None,
            f"Digital Forensic Report - {inc['incident_type']} ({incident_id})",
            generated_by, str(output_path), report_size, report_hash,
            f"Forensic report for {inc['incident_type']} incident {incident_id}. SHA-256: {report_hash[:16]}...",
            "Completed"
        ))

        # Record in Chain of Custody if evidence was linked
        if evd:
            ChainOfCustodyService.record_action(
                evidence_id=evd["id"],
                action="REPORT_GENERATED",
                actor=generated_by,
                actor_role="Forensic Reporting Module",
                file_hash=report_hash,
                description=f"Official forensic investigation report generated: {filename} (SHA-256: {report_hash})",
                verification_result="GENERATED"
            )

        return {
            "report_id": report_id,
            "filename": filename,
            "file_path": str(output_path),
            "sha256_hash": report_hash,
            "file_size": report_size
        }
