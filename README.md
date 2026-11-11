# EATC — AI-Powered SOC Triage Tool

SOC analysts cannot manually review every network flow on an enterprise network, and signature-based IDS/IPS rules miss new or multi-vector attacks. This project trains a Random Forest classifier on CIC-IDS2017 network flow features to label each flow as BENIGN or a specific attack type. The model is packaged into a Streamlit dashboard that accepts a CSV of flows, scores every row with a confidence value, and exports annotated results.

## Contents

| File | Description |
| --- | --- |
| `EATC-Assignment-2-Report.docx` | Full assignment report |
| `SOC-Triage-Tool.ipynb` | Notebook: preprocessing, training, evaluation, model export |
| `app/app.py` | Streamlit triage dashboard |
| `app/requirements.txt` | Python dependencies |
| `app/rf_model.pkl` | Trained Random Forest model |
| `app/label_encoder.pkl` | Label encoder for attack-class names |
| `app/feature_columns.pkl` | Expected feature schema for uploaded CSVs |
| `app/streamlit_test_sample.csv` | Sample input for testing the app |

## Approach

1. **Dataset.** Six CIC-IDS2017 `MachineLearningCSV` files (Monday benign baseline, Tuesday brute force, Wednesday DoS, Thursday web attacks and infiltration, Friday DDoS), all passed through CICFlowMeter into 79 flow features. PortScan and Botnet captures were excluded as reconnaissance and behaviourally ambiguous respectively.
2. **Sampling.** A randomised 15% sample of each file was concatenated into one master set of 352,986 rows.
3. **Missing values and duplicates.** Missing `Flow Bytes/s` values were filled with the column median rather than zero, since zero is a valid traffic rate. Identical rows were dropped keeping the first occurrence, leaving 334,107 rows.
4. **Irrelevant columns.** Duplicated feature pairs were reduced to one clear column each (`Fwd Header Length.1`, the `Subflow` packet/byte counts, `Avg Fwd Segment Size`), and single-value constant columns were removed. Distinct TCP flag columns were kept because they carry different semantics.
5. **Feature engineering.** No new features were synthesised; CICFlowMeter already provides the statistical flow measurements, so adding derived columns would duplicate information.
6. **Outliers.** Extreme values were deliberately retained because high byte and packet rates are genuine DoS/DDoS signatures. Only logically invalid values (infinities from zero-duration rates, negative durations and counts) were set to NaN and median-filled.
7. **Rare classes.** Heartbleed, Infiltration and Web Attack - Sql Injection had too few records for a reliable stratified split and were too small for SMOTE, so they were removed, leaving 334,095 rows and ten classes.
8. **Encoding and split.** `LabelEncoder` produced `Encoded_Label`; `Label` and `Encoded_Label` were both dropped from `X` to avoid leakage. An 80:20 stratified split (`random_state=42`) gave 267,276 training and 66,819 test rows over 65 features.
9. **Model.** `RandomForestClassifier` with `n_estimators=100`, `class_weight="balanced"`, `random_state=42`, `n_jobs=-1`. No feature scaling, since tree splits are threshold-based.
10. **Export.** Model, label encoder and ordered feature list saved with joblib for the app to load.

## Results

- Overall test accuracy: **99.57%** on 66,819 held-out flows.
- Weighted average F1: 1.00; macro average F1: 0.85 — the gap reflects the small rare classes.
- BENIGN, DDoS and DoS Hulk all scored precision, recall and F1 of 0.99–1.00.
- Weakest classes: Web Attack - XSS (precision 0.14, recall 0.71, F1 0.23) and Web Attack - Brute Force (precision 0.35, recall 0.58, F1 0.44), both with very few test samples (21 and 50).
- DoS Slowhttptest had high recall (0.99) but lower precision (0.86), so some other traffic was mislabelled as that class.
- The confusion matrix shows BENIGN errors spread thinly across web-attack and DoS classes rather than concentrated in one.

## Application

The analyst uploads a CSV of CICFlowMeter-style flow records. Because raw captures include columns removed during training (Flow ID, IP addresses, Timestamp), `preprocess()` strips column names, drops any `Label`/`Encoded_Label`, replaces infinities, fills missing expected features with zero, and reorders columns to the saved schema; missing and ignored columns are reported in the UI. The model predicts a class per row, `inverse_transform()` restores readable labels, and `predict_proba()` supplies the confidence score (probability of the predicted class). Results appear as summary metrics, a traffic-type bar chart, a table filterable to malicious-only flows, and a downloadable annotated CSV. The app is deployed on Streamlit Community Cloud, which builds from `requirements.txt` and loads the cached artifacts once per session.

## Running locally

```bash
cd app
pip install -r requirements.txt
streamlit run app.py
```

## Key takeaways

- Median imputation suited skewed network rates better than mean or zero, and preserving extreme values kept attack signatures intact.
- Removing duplicated rows and constant columns cut noise without hurting detection of the major classes.
- High headline accuracy hid weak precision on the smallest web-attack classes, which is why per-class recall and F1 mattered more than the total.
- Caching the serialised model let a 170,366-row raw capture be triaged in seconds on the deployed app.
- Schema alignment, not model quality, was the main engineering risk when accepting arbitrary analyst-supplied CSVs.

## Notes

- The raw dataset (MachineLearningCSV) is not included in this repository because of its size; it is the public CICIDS2017 MachineLearningCVE CSV set.
- No credentials or API keys are stored in this repository.
- The model cannot detect Heartbleed, Infiltration or SQL Injection, as those classes were excluded from training.
