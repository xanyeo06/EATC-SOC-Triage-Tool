"""
AI-Powered SOC Triage Tool
--------------------------
Emerging AI Trends in Cybersecurity — Assignment 2

Analysts upload a CSV of network flow records (same feature format as
CIC-IDS2017 / CICFlowMeter output). The app runs each flow through a
trained Random Forest model and classifies it as BENIGN or one of the
attack types (DDoS, DoS Hulk, Web Attack - XSS, etc.), then presents a
triage dashboard so an analyst can quickly see what needs attention.
"""

import io

import joblib
import numpy as np
import pandas as pd
import streamlit as st

# ------------------------------------------------------------------
# Page config
# ------------------------------------------------------------------
st.set_page_config(
    page_title="SOC Triage Tool",
    page_icon="🛡️",
    layout="wide",
)

MODEL_PATH = "rf_model.pkl"
ENCODER_PATH = "label_encoder.pkl"
FEATURES_PATH = "feature_columns.pkl"


# ------------------------------------------------------------------
# Cached model loading — runs once, not on every interaction
# ------------------------------------------------------------------
@st.cache_resource
def load_artifacts():
    model = joblib.load(MODEL_PATH)
    label_encoder = joblib.load(ENCODER_PATH)
    feature_columns = joblib.load(FEATURES_PATH)
    return model, label_encoder, feature_columns


def preprocess(df: pd.DataFrame, feature_columns: list[str]) -> tuple[pd.DataFrame, list[str], list[str]]:
    """Clean an uploaded CSV and align it to the training feature schema.

    Returns the aligned feature dataframe plus lists of any columns
    that were missing (filled with 0) or ignored (extra/unused), so
    the analyst can be warned about schema mismatches.
    """
    df = df.copy()
    df.columns = df.columns.str.strip()

    # Drop label columns if the analyst uploaded an already-labelled file
    df = df.drop(columns=[c for c in ["Label", "Encoded_Label"] if c in df.columns])

    # Same cleaning steps used in training: inf -> NaN -> median fill
    df = df.replace([np.inf, -np.inf], np.nan)

    missing_cols = [c for c in feature_columns if c not in df.columns]
    extra_cols = [c for c in df.columns if c not in feature_columns]

    for col in missing_cols:
        df[col] = 0

    df = df[feature_columns]  # exact order the model expects

    for col in df.columns:
        if df[col].isna().any():
            df[col] = df[col].fillna(df[col].median() if df[col].notna().any() else 0)

    return df, missing_cols, extra_cols


# ------------------------------------------------------------------
# Sidebar
# ------------------------------------------------------------------
with st.sidebar:
    st.title("🛡️ SOC Triage Tool")
    st.markdown(
        "AI-powered network intrusion classifier trained on the "
        "**CIC-IDS2017** dataset using a **Random Forest** model."
    )
    st.markdown("---")
    st.markdown("**How to use**")
    st.markdown(
        "1. Upload a CSV of network flow records\n"
        "2. The model classifies each flow\n"
        "3. Review the triage summary below\n"
        "4. Download the annotated results"
    )
    st.markdown("---")
    st.caption(
        "Built for Emerging AI Trends in Cybersecurity: Assignment 2. "
        "This is a decision-support tool, not a replacement for analyst judgement."
    )

# ------------------------------------------------------------------
# Load model
# ------------------------------------------------------------------
try:
    model, label_encoder, feature_columns = load_artifacts()
except FileNotFoundError:
    st.error(
        "Model files not found. Make sure `rf_model.pkl`, `label_encoder.pkl`, "
        "and `feature_columns.pkl` are in the same folder as `app.py` "
        "(see `add_to_notebook_model_export.py` for how to generate them)."
    )
    st.stop()

st.title("Network Traffic Triage Dashboard")
st.write(
    "Upload a CSV of network flow records (CICFlowMeter-style columns, "
    "same format as the CIC-IDS2017 dataset) to classify traffic as "
    "benign or malicious."
)

uploaded_file = st.file_uploader("Upload network flow CSV", type=["csv"])

if uploaded_file is None:
    st.info("Waiting for a CSV upload to begin analysis.")
    st.stop()

# ------------------------------------------------------------------
# Read + preprocess
# ------------------------------------------------------------------
try:
    raw_df = pd.read_csv(uploaded_file)
except Exception as e:
    st.error(f"Could not read the uploaded file: {e}")
    st.stop()

with st.spinner("Preprocessing and classifying network flows..."):
    X, missing_cols, extra_cols = preprocess(raw_df, feature_columns)
    y_pred_encoded = model.predict(X)
    y_pred_labels = label_encoder.inverse_transform(y_pred_encoded.astype(int))

    # Confidence = probability of the predicted class
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)
        confidence = proba.max(axis=1)
    else:
        confidence = np.full(len(X), np.nan)

results_df = raw_df.copy()
results_df["Predicted_Label"] = y_pred_labels
results_df["Confidence"] = confidence

if missing_cols:
    st.warning(
        f"{len(missing_cols)} expected feature column(s) were missing from your "
        f"upload and were filled with 0 (e.g. {missing_cols[:5]}...). "
        "Predictions on this data may be less reliable."
    )
if extra_cols:
    st.caption(f"{len(extra_cols)} extra column(s) in your upload were ignored (not used by the model).")

# ------------------------------------------------------------------
# Triage summary
# ------------------------------------------------------------------
total_flows = len(results_df)
benign_count = int((results_df["Predicted_Label"] == "BENIGN").sum())
malicious_count = total_flows - benign_count
malicious_pct = (malicious_count / total_flows * 100) if total_flows else 0

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Flows Analyzed", f"{total_flows:,}")
col2.metric("Benign", f"{benign_count:,}")
col3.metric("Flagged as Malicious", f"{malicious_count:,}")
col4.metric("Malicious Rate", f"{malicious_pct:.2f}%")

if malicious_count > 0:
    st.error(f"⚠️ {malicious_count} flow(s) flagged as potentially malicious — review below.")
else:
    st.success("✅ No malicious traffic detected in this batch.")

st.markdown("---")

# ------------------------------------------------------------------
# Breakdown chart
# ------------------------------------------------------------------
st.subheader("Traffic Type Breakdown")
label_counts = results_df["Predicted_Label"].value_counts()
st.bar_chart(label_counts)

# ------------------------------------------------------------------
# Detailed table with filtering
# ------------------------------------------------------------------
st.subheader("Flow-Level Results")

view_option = st.radio(
    "Show:",
    ["All flows", "Malicious only"],
    horizontal=True,
)

display_df = results_df if view_option == "All flows" else results_df[results_df["Predicted_Label"] != "BENIGN"]

display_cols = ["Predicted_Label", "Confidence"] + [c for c in raw_df.columns if c not in ("Label", "Encoded_Label")]
st.dataframe(display_df[display_cols], width='stretch', height=400)

# ------------------------------------------------------------------
# Download
# ------------------------------------------------------------------
csv_buffer = io.StringIO()
results_df.to_csv(csv_buffer, index=False)
st.download_button(
    "Download annotated results as CSV",
    data=csv_buffer.getvalue(),
    file_name="soc_triage_results.csv",
    mime="text/csv",
)
