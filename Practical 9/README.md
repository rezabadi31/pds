# Practical 9: Simple Classifier for Attack Detection

## Project Title
**"To build a Simple Classifier to detect the attacks."**

## Laboratory Course
**Python for Data Science (PDS) — Cybersecurity Analytics Practicals**

---

## 1. Objective & Scope
The objective of Practical 9 is to train, evaluate, and compare fundamental machine learning classification models to detect and classify multi-class web application cyberattacks using the telemetry features engineered in **Practical 5** (`Practical 5/data/processed/feature_engineered_access_logs.csv`).

All data processing, model training, evaluation, and visualization are conducted exclusively using free and open-source Python libraries:
- **scikit-learn**: Data splitting, feature scaling, model fitting (`LogisticRegression`, `RandomForestClassifier`), and classification metrics.
- **pandas & NumPy**: Vectorized data manipulation, matrix cleaning, and table exports.
- **matplotlib & seaborn**: Publication-ready visual diagnostic plots.
- **joblib**: Model persistence and artifact serialization.

No paid, proprietary tools, cloud services, or closed APIs are used. Everything runs 100% locally.

---

## 2. Directory Structure

```text
D:\Pds Practicals\Practical 9\
│
├── outputs\
│   ├── data\
│   │   ├── logistic_regression_metrics.csv      # Per-class precision, recall, F1, and support
│   │   ├── random_forest_metrics.csv            # Per-class precision, recall, F1, and support
│   │   ├── model_comparison.csv                 # Macro & weighted comparison between models
│   │   ├── random_forest_feature_importance.csv # All 66 features ranked by Gini importance
│   │   └── balanced_experiment_comparison.csv   # Part 13: Natural vs Balanced experiment metrics
│   │
│   ├── models\
│   │   ├── logistic_regression.joblib           # Trained LR model + fitted StandardScaler
│   │   └── random_forest.joblib                 # Trained Random Forest ensemble model
│   │
│   ├── plots\
│   │   ├── logistic_regression_confusion_matrix.png # Multiclass confusion matrix
│   │   ├── random_forest_confusion_matrix.png       # Multiclass confusion matrix
│   │   ├── model_accuracy_comparison.png            # Accuracy vs Macro F1 comparison
│   │   ├── random_forest_top20_features.png         # Top 20 most discriminative features
│   │   └── class_distribution.png                   # Stratified train vs test distribution
│   │
│   └── reports\
│       ├── logistic_regression_report.txt       # Detailed text report for Logistic Regression
│       ├── random_forest_report.txt             # Detailed text report for Random Forest
│       └── classifier_report.txt                # Comprehensive 13-section technical report
│
├── src\
│   ├── __init__.py                              # Package marker
│   ├── config.py                                # Paths, parameters, and hyperparameters
│   ├── inspector.py                             # Part 1: Dataset loading and diagnostics
│   ├── preparer.py                              # Parts 2 & 3: Leakage removal and data cleaning
│   ├── trainer.py                               # Parts 4, 5, 6, 7: Split, scaling & model training
│   ├── evaluator.py                             # Parts 8, 9, 10, 11, 12, 14: Evaluation & plotting
│   ├── balanced_validator.py                    # Part 13: Practical 6 balanced validation
│   ├── reporter.py                              # Part 16: Final report synthesis
│   ├── run_practical9.py                        # Pipeline execution script
│   └── verify_classifier.py                     # Part 15: 14-point automated test suite
│
├── run_practical9.py                            # Root execution entrypoint
├── verify_classifier.py                         # Root verification entrypoint
├── requirements.txt                             # Python dependencies
└── README.md                                    # Practical documentation
```

---

## 3. Workflow & Methodology

1. **Part 1 — Data Inspection**:
   Loads the 1,492,182 records from Practical 5. Audits total columns, target distribution across 6 classes (`benign`, `brute_force`, `path_traversal`, `xss`, `command_injection`, `sqli`), missing values, and infinite values.
2. **Part 2 — Prepare Features & Eliminate Leakage**:
   Extracts `y = label`. Strictly excludes all potential target leakage attributes (`label`, `label_reason`, `target`, `anomaly_score`) and unencoded text/raw identifier columns (`timestamp`, `client_ip`, `user_agent`, `payload`, `resource_requested`). Isolates 66 valid numeric features.
3. **Part 3 — Data Cleaning**:
   Replaces `+inf` and `-inf` with `np.nan`. Employs `SimpleImputer(strategy="median")` to handle missing numeric values without injecting arbitrary artificial noise. Confirms zero residual NaNs or infinite values.
4. **Part 4 — Stratified Train / Test Partitioning**:
   Splits data into 80% training (1,193,745 records) and 20% testing (298,437 records) using `stratify=y` and `random_state=42`. Crucially, the 20% test partition remains completely untouched and un-augmented.
5. **Part 5 — Feature Scaling**:
   Applies `StandardScaler` strictly fitted on `X_train` and transforms both `X_train` and `X_test` for Logistic Regression. Random Forest utilizes the unscaled numeric feature matrix directly.
6. **Part 6 & 7 — Model Training**:
   - **Logistic Regression**: Multinomial with L2 regularization, `max_iter=300`, `random_state=42`, and `class_weight="balanced"`.
   - **Random Forest**: Ensemble of 100 decision trees, `random_state=42`, `n_jobs=-1`, and `class_weight="balanced"`.
   - Both models are serialized with metadata via `joblib`.
7. **Parts 8 - 12 — Evaluation & Visual Diagnostics**:
   Computes multiclass confusion matrices, full classification reports, model comparison tables, Gini feature importance rankings (Top 20 horizontal bar chart), and an Accuracy vs. Macro F1 comparison chart.
8. **Part 13 — Balanced-Data Validation Experiment**:
   Trains models on Practical 6's balanced training dataset (60,000 records) and evaluates against Practical 6's untouched test set (298,437 records) to compare synthetic balancing against class weighting.
9. **Part 15 — Verification**:
   Runs 14 automated unit and integrity checks to ensure zero data leakage, correct metric computation, and artifact presence.

---

## 4. Execution & Verification

Run the full end-to-end classification pipeline:
```bash
python run_practical9.py
```
*(or `python src/run_practical9.py`)*

Run the automated verification suite:
```bash
python verify_classifier.py
```
*(or `python src/verify_classifier.py`)*
