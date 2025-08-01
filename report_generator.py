from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def generate_pdf(df, output_path="report.pdf"):
    c = canvas.Canvas(output_path, pagesize=letter)
    c.setFont("Helvetica", 12)
    c.drawString(100, 750, "Clinical Variant Report")
    y = 700
    for _, row in df.iterrows():
        line = f"{row['CHROM']}:{row['POS']} {row['REF']}>{row['ALT']} | ClinVar: {row['ClinVar']} | ACMG: {row['ACMG']}"
        c.drawString(50, y, line)
        y -= 20
        if y < 50:
            c.showPage()
            y = 750
    c.save()
