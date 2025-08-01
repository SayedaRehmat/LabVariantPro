import streamlit as st
import firebase_admin
from firebase_admin import credentials, auth
import vcfpy
import pandas as pd
import requests
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# ─────────── Firebase Admin Initialization ───────────
if not firebase_admin._apps:
    cred = credentials.Certificate(st.secrets["firebase"])  # ← ✅ FIXED LINE
    firebase_admin.initialize_app(cred)

# ─────────── Streamlit UI ───────────
st.set_page_config(page_title="LabVariantPro", layout="wide")
st.title("🧬 LabVariantPro – VCF Annotation Tool")

st.sidebar.header("🔐 Lab Login")
email = st.sidebar.text_input("Lab Email")

if st.sidebar.button("Login"):
    try:
        user = auth.get_user_by_email(email)
        st.session_state["user"] = user.email
        st.sidebar.success(f"✅ Logged in as: {user.email}")
    except:
        st.sidebar.error("❌ Email not found. Please contact admin.")

if "user" not in st.session_state:
    st.warning("Please log in to access the tool.")
    st.stop()

st.success(f"✅ Logged in as: {st.session_state['user']}")

# ─────────── Annotation Logic ───────────
def annotate_variant(chrom, pos, ref, alt):
    hgvs = f"{chrom}:g.{pos}{ref}>{alt}"
    url = f"https://myvariant.info/v1/variant/{hgvs}"
    try:
        res = requests.get(url)
        if res.status_code != 200:
            return {'clinvar': 'NA', 'acmg': 'Uncertain', 'rules_applied': []}
        data = res.json()
        clinvar = data.get('clinvar', {}).get('clinical_significance', 'NA')
        af = data.get('gnomad', {}).get('af', 0)
        rules = []
        if af is not None:
            if af < 0.0001: rules.append('PM2')
            elif af > 0.05: rules.append('BA1')
        if 'mutationtaster' in data:
            rules.append('PP3')
        if 'pathogenic' in str(clinvar).lower():
            acmg = 'Likely Pathogenic'
        elif 'benign' in str(clinvar).lower():
            acmg = 'Likely Benign'
        else:
            acmg = 'Uncertain'
        return {
            'clinvar': clinvar,
            'gnomad_af': af,
            'acmg': acmg,
            'rules_applied': rules
        }
    except:
        return {'clinvar': 'Error', 'acmg': 'Error', 'rules_applied': []}

# ─────────── VCF File Parser ───────────
def parse_vcf(file_obj):
    reader = vcfpy.Reader(file_obj)
    records = []
    for record in reader:
        chrom = record.CHROM
        pos = record.POS
        ref = record.REF
        alt = record.ALT[0].value
        qual = record.QUAL
        ann = annotate_variant(chrom, pos, ref, alt)
        records.append({
            'CHROM': chrom,
            'POS': pos,
            'REF': ref,
            'ALT': alt,
            'QUAL': qual,
            'ClinVar': ann['clinvar'],
            'gnomAD_AF': ann.get('gnomad_af'),
            'ACMG': ann['acmg'],
            'Rules': ', '.join(ann['rules_applied'])
        })
    return pd.DataFrame(records)

# ─────────── PDF Report Generator ───────────
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

# ─────────── Upload + Output ───────────
uploaded_file = st.file_uploader("📂 Upload your `.vcf` file", type=["vcf"])

if uploaded_file:
    try:
        with io.TextIOWrapper(uploaded_file, encoding="utf-8") as vcf_io:
            df = parse_vcf(vcf_io)
            st.success("✅ File parsed successfully.")
            st.dataframe(df)

            st.download_button("📥 Download CSV", df.to_csv(index=False).encode(), "labvariant_report.csv")

            if st.button("📄 Generate PDF"):
                generate_pdf(df)
                with open("report.pdf", "rb") as f:
                    st.download_button("Download PDF", f, "report.pdf")

    except Exception as e:
        st.error(f"❌ Error processing VCF: {e}")
