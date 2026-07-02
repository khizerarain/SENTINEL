from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
from rich.console import Console
from rich.panel import Panel

from dns_lookup import run_dns
from headers import get_security_header_results
from ports import scan_ports
from scanner import run_scan
from ssl_checker import get_ssl_details
from utils import compute_security_score, make_request

console = Console()


def _build_markdown(domain: str, score: int, ssl_data: dict, header_data: dict, dns_text: str, open_ports: list[int], recommendations: list[str]) -> str:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    md = [
        "# SENTINEL Security Report",
        f"**Domain:** {domain}",
        f"**Generated:** {now}",
        "",
        f"## Security Score: {score}/100",
        "",
        "## SSL Certificate",
        f"- Issuer: {ssl_data.get('issuer', 'N/A')}",
        f"- Expires: {ssl_data.get('not_after', 'N/A')}",
        f"- Days Remaining: {ssl_data.get('days_remaining', 'N/A')}",
        "",
        "## Security Headers",
        *(f"- {header}" for header in header_data.get('present_headers', [])),
        "",
        "## DNS Records",
        dns_text,
        "",
        "## Open Ports",
        *(f"- {port}" for port in open_ports),
        "",
        "## Recommendations",
        *(f"- {item}" for item in recommendations),
    ]
    return "\n".join(md)


def _collect_dns_markdown(domain: str) -> str:
    import dns.resolver

    lines = []
    for record_type in ["A", "AAAA", "MX", "TXT", "NS"]:
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=10)
            for rdata in answers:
                lines.append(f"- {record_type}: {rdata}")
        except Exception:
            lines.append(f"- {record_type}: N/A")
    return "\n".join(lines)


def _create_pdf(filename: str, domain: str, score: int, ssl_data: dict, header_data: dict, dns_text: str, open_ports: list[int], recommendations: list[str]) -> None:
    doc = SimpleDocTemplate(filename, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
    styles = getSampleStyleSheet()
    story = []
    title_style = styles["Title"]
    heading_style = ParagraphStyle("Heading", parent=styles["Heading2"], textColor=colors.cyan)
    normal_style = styles["Normal"]
    mono_style = ParagraphStyle("Mono", parent=styles["Code"], fontName="Courier", fontSize=10)

    story.append(Paragraph("SENTINEL Security Report", title_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Domain: {domain}", normal_style))
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", normal_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Security Score: {score}/100", heading_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph("SSL Certificate", styles["Heading3"]))
    story.append(Paragraph(f"Issuer: {ssl_data.get('issuer', 'N/A')}", normal_style))
    story.append(Paragraph(f"Expires: {ssl_data.get('not_after', 'N/A')}", normal_style))
    story.append(Paragraph(f"Days Remaining: {ssl_data.get('days_remaining', 'N/A')}", normal_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Security Headers", styles["Heading3"]))
    story.append(Paragraph(", ".join(header_data.get('present_headers', [])) or "None", mono_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph("DNS Records", styles["Heading3"]))
    story.append(Paragraph(dns_text.replace("\n", "<br/>"), mono_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Open Ports", styles["Heading3"]))
    story.append(Paragraph(", ".join(str(port) for port in open_ports) or "None", normal_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Recommendations", styles["Heading3"]))
    for recommendation in recommendations:
        story.append(Paragraph(f"• {recommendation}", normal_style))
    doc.build(story)


def run_report(domain: str) -> None:
    ssl_data = get_ssl_details(domain, silent=True)
    header_data = get_security_header_results(domain)
    dns_text = _collect_dns_markdown(domain)
    port_data = scan_ports(domain, silent=True)
    results = {
        "https_enabled": True,
        "valid_ssl": ssl_data.get("valid_ssl", False),
        "headers_present": header_data.get("present_headers", []),
    }
    score = compute_security_score(results)

    recommendations = []
    missing_headers = header_data.get("missing_headers", [])
    if missing_headers:
        recommendations.append(f"Add missing security headers: {', '.join(missing_headers)}")
    if ssl_data.get("valid_ssl") is False:
        recommendations.append("Renew or fix the SSL/TLS certificate.")
    if ssl_data.get("days_remaining") is not None and ssl_data["days_remaining"] < 30:
        recommendations.append("Renew SSL certificate before expiration.")
    if port_data.get("open_ports"):
        recommendations.append(f"Review exposed open ports: {', '.join(str(port) for port in port_data['open_ports'])}")

    markdown = _build_markdown(domain, score, ssl_data, header_data, dns_text, port_data.get("open_ports", []), recommendations)
    md_filename = f"sentinel_report_{domain.replace('.', '_')}.md"
    pdf_filename = f"sentinel_report_{domain.replace('.', '_')}.pdf"

    with open(md_filename, "w", encoding="utf-8") as md_file:
        md_file.write(markdown)

    _create_pdf(pdf_filename, domain, score, ssl_data, header_data, dns_text, port_data.get("open_ports", []), recommendations)

    console.print(Panel(
        f"Report generated:\n- {md_filename}\n- {pdf_filename}",
        title="Report Complete",
        border_style="green"
    ))
