import streamlit as st
import vcfpy
import requests
import pandas as pd
import io
import pyrebase
from report_generator import generate_pdf
from firebase_config import firebaseConfig

# Firebase Auth
firebase = pyrebase.initialize_app(firebaseConfig)
auth = firebase.auth()

st.set_page_config(page_title="LabVariantPro", layout="wide")
st.title("🧬 LabVariantPro – VCF Annotation Tool")

# Login UI in sidebar
with st.sidebar:
    st.header("🔐 Login or Sign Up")
    choice = st.radio("Select Option", ["Login", "Sign Up"])
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if choice == "Login":
        if st.button("Login"):
            try:
                user = auth.sign_in_with_email_and_password(email, password)
                st.session_state["user"] = user["email"]
                st.success(f"Logged in as {user['email']}")
            except:
                st.error("Login failed. Please check credentials.")
    else:
        if st.button("Sign Up"):
            try:
                auth.create_user_with_email_and_password(email, password)
                st.success("Account created. Please login.")
            except:
                st.error("Signup failed.")

# Require login
if "user" not in st.session_state:
    st.warning("Please log in to access annotation.")
    st.stop()

# Annotate variant
def annotate_variant(chrom, pos, ref, alt):
    hgvs = f"{chrom}:g.{pos}{ref}>{alt}"
    url = f"https://myvariant.info/v1/variant/{hgvs}"
    try:
        res = requests.get(url)
        data = res.json() if res.status_code == 200 else {}
        clinvar = data.get('clinvar', {}).get('clinical_significance', 'NA')
        af = data.get('gnomad', {}).get('af', 0)
        rules = []
        if af is not None:
            if af < 0.0001: rules.append('PM2')
            elif af > 0.05: rules.append('BA1')
        if 'mutationtaster' in data:
            rules.append('PP3')
        acmg = (
            "Likely Pathogenic" if 'pathogenic' in str(clinvar).lower()
            else "Likely Benign" if 'benign' in str(clinvar).lower()
            else "Uncertain"
        )
        return {
            'clinvar': clinvar,
            'gnomad_af': af,
            'acmg': acmg,
            'rules_applied': rules
        }
    except:
        return {'clinvar': 'Error', 'acmg': 'Error', 'rules_applied': []}

# Parse VCF
def parse_vcf(file_obj):
    reader = vcfpy.Reader(file_obj)
    records = []
    for rec in reader:
        chrom = rec.CHROM
        pos = rec.POS
        ref = rec.REF
        alt = rec.ALT[0].value
        qual = rec.QUAL
        ann = annotate_variant(chrom, pos, ref, alt)
        records.append({
            'CHROM': chrom, 'POS': pos, 'REF': ref, 'ALT': alt,
            'QUAL': qual,
            'ClinVar': ann['clinvar'],
            'gnomAD_AF': ann.get('gnomad_af'),
            'ACMG': ann['acmg'],
            'Rules': ', '.join(ann['rules_applied'])
        })
    return pd.DataFrame(records)

# Upload Section
uploaded_file = st.file_uploader("Upload a `.vcf` file", type=["vcf"])

if uploaded_file:
    try:
        with io.TextIOWrapper(uploaded_file, encoding='utf-8') as vcf_io:
            df = parse_vcf(vcf_io)
            st.session_state["df"] = df
            st.success("✅ File parsed successfully.")
            st.dataframe(df)

            st.download_button("📥 Download CSV", df.to_csv(index=False).encode(), "labvariant_report.csv")
            if st.button("📄 Generate PDF"):
                generate_pdf(df, "report.pdf")
                with open("report.pdf", "rb") as f:
                    st.download_button("Download PDF", f, "report.pdf")

    except Exception as e:
        st.error(f"❌ Error processing file: {e}")
