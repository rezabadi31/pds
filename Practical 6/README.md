# Practical 6 — Dataset Balancing for ML and Deep Learning Training

## Title
**"To do the balancing of the Dataset for ML training/Deep Learning training."**

## Course
Predictive Data Science (PDS)

---

## 1. Objective
The primary objective of Practical 6 is to resolve severe class imbalance in intrusion detection and honeypot telemetry. In real-world enterprise networks, benign traffic vastly outnumbers attack attempts (99.71% benign vs. 0.29% attacks, an imbalance ratio of **9,298 : 1**). Training standard Machine Learning or Deep Learning architectures directly on this raw distribution causes classifiers to predict the majority class trivially, leading to high nominal accuracy but catastrophic false-negative rates for critical threats.

Practical 6 implements:
1. Exploratory class imbalance quantification and ratio analysis across all 6 classes.
2. Target leakage elimination and strictly partitioned stratified 80/20 train/test splitting.
3. Random Undersampling of majority observations.
4. Random Oversampling of minority classes.
5. Synthetic Minority Over-sampling Technique (**SMOTE**) via k-NN manifold vector interpolation.
6. Comparative evaluation across balancing strategies and selection of the final training dataset.
7. Preservation of a 100% untouched, un-balanced test dataset to ensure rigorous, unbiased downstream model evaluation.

---

## 2. Input Telemetry & Cardinal Data Science Rules
- **Primary Input:** `D:\Pds Practicals\Practical 5\data\processed\feature_engineered_access_logs.csv` (1,492,182 records × 80 columns).
- **Golden Rule of Balancing:** Balancing operations (SMOTE, Random Oversampling, Undersampling) must **NEVER** be applied before splitting the dataset. Applying resamplers to the entire dataset results in synthetic or duplicated test records, causing severe data leakage and invalid benchmark metrics.
- **Untouched Test Guarantee:** The test partition (20% = 298,437 records) is saved to `test_dataset.csv` immediately after splitting and remains completely un-balanced, preserving the true operational distribution.
- **Zero Target Leakage:** Columns `label` and `label_reason` are strictly removed from feature matrix $X$. All non-numeric metadata strings are isolated.

```text
                      Original Dataset (1,492,182 records)
                                       |
                                       v
                    Stratified Train/Test Split (80% / 20%)
                                       |
                   +-------------------+-------------------+
                   |                                       |
                   v                                       v
        Training Fold (1,193,745 records)       Test Fold (298,437 records)
                   |                                       |
         +---------+---------+                             v
         |         |         |                 [Untouched Test Dataset]
         v         v         v                  (data/processed/test_dataset.csv)
   Undersample  Oversample  SMOTE
         |         |         |
         +---------+---------+
                   |
                   v
      [Selected Balanced Dataset]
   (data/processed/balanced_training_dataset.csv)
```

---

## 3. Directory Structure
```text
D:\Pds Practicals\Practical 6\
│
├── data\
│   └── processed\
│       ├── test_dataset.csv                     # 100% untouched test evaluation partition (298,437 records)
│       ├── balanced_train_undersampled.csv      # RandomUnderSampler balanced training set (768 records)
│       ├── balanced_train_random_oversampled.csv# RandomOverSampler balanced training set (60,000 records)
│       ├── balanced_train_smote.csv             # SMOTE synthetic balanced training set (60,000 records)
│       └── balanced_training_dataset.csv        # Final selected training dataset for ML/DL (60,000 records)
│
├── outputs\
│   ├── reports\
│   │   ├── balancing_comparison.csv             # Numerical comparison table across all balancing methods
│   │   └── balancing_report.txt                 # Comprehensive 14-section technical report
│   └── plots\
│       ├── original_class_distribution.png      # Pre-split telemetry class distribution (Log Scale)
│       ├── training_class_distribution.png      # Training partition distribution before balancing (Log Scale)
│       ├── undersampling_distribution.png       # Random Undersampling class distribution
│       ├── random_oversampling_distribution.png # Random Oversampling class distribution
│       ├── smote_distribution.png               # SMOTE synthetic class distribution
│       ├── final_balanced_distribution.png      # Final selected balanced training distribution
│       └── balancing_methods_comparison.png     # Log-scale comparison across all 4 training partitions
│
├── src\
│   ├── __init__.py
│   ├── config.py                                # Centralized directory paths and hyperparameters
│   ├── inspector.py                             # Parts 1 & 2: Dataset inspection & imbalance profiling
│   ├── splitter.py                              # Parts 3 & 4: Target leakage elimination & train/test split
│   ├── balancers.py                             # Parts 5, 6, 7 & 9: Undersampling, Oversampling, SMOTE engines
│   ├── plots.py                                 # Part 12: Publication-grade diagnostic bar charts
│   ├── reporter.py                              # Parts 8 & 13: Comparative matrix and technical report
│   └── verify_balancing.py                      # Part 11: Automated 14-point test verification suite
│
├── run_practical6.py                            # Master pipeline entrypoint
├── requirements.txt                             # Python dependencies (imblearn, scikit-learn, etc.)
└── README.md                                    # Documentation & viva preparation guide
```

---

## 4. Class Imbalance Profile

Across the 1,492,182 records in the honeypot telemetry dataset, the ground-truth distribution exhibits extreme skewness:

| Class | Total Records | Percentage | Training Count (80%) | Testing Count (20%) |
| :--- | ---: | ---: | ---: | ---: |
| **`benign`** | 1,487,823 | 99.7079% | 1,190,258 | 297,565 |
| **`brute_force`** | 1,342 | 0.0899% | 1,074 | 268 |
| **`path_traversal`** | 1,098 | 0.0736% | 878 | 220 |
| **`xss`** | 954 | 0.0639% | 763 | 191 |
| **`command_injection`** | 805 | 0.0540% | 644 | 161 |
| **`sqli`** | 160 | 0.0107% | 128 | 32 |
| **Total** | **1,492,182** | **100.00%** | **1,193,745** | **298,437** |

$$\text{Imbalance Ratio} = \frac{\text{Count}(\text{benign})}{\text{Count}(\text{sqli})} = \frac{1,487,823}{160} = \mathbf{9,298.89 : 1}$$

---

## 5. Comparative Evaluation of Balancing Strategies

| Balancing Strategy | Total Records | benign | brute_force | path_traversal | xss | command_injection | sqli | Methodological Pros & Cons |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| **Original Training** | 1,193,745 | 1,190,258 | 1,074 | 878 | 763 | 644 | 128 | Severe majority bias. Classifiers will ignore minority attacks. |
| **Random Undersampling** | 768 | 128 | 128 | 128 | 128 | 128 | 128 | **Pro:** Eliminates majority bias; fast. **Con:** Discards >99.9% of benign variance. |
| **Random Oversampling** | 60,000 | 10,000 | 10,000 | 10,000 | 10,000 | 10,000 | 10,000 | **Pro:** Retains all samples. **Con:** Duplicates identical rows, causing decision boundary memorization. |
| **SMOTE (Synthetic)** | **60,000** | **10,000** | **10,000** | **10,000** | **10,000** | **10,000** | **10,000** | **Pro:** Generates continuous synthetic points along feature manifolds; superior generalization. |

### Rationale for Selecting SMOTE as Final Training Dataset
**SMOTE** was selected because it generates synthetic feature vectors via linear interpolation between $k$-nearest neighbors ($k=5$):
$$x_{new} = x_i + \lambda \times (x_{zi} - x_i) \quad \text{where } \lambda \sim U(0, 1)$$
Unlike Random Oversampling (which copies identical points and causes tree algorithms and deep neural networks to overfit to repeated points), SMOTE populates the convex hull of the minority classes, expanding decision boundaries and enhancing classifier robustness on unseen attack vectors.

---

## 6. Verification Suite & Quality Assurance

Run the automated test suite:
```powershell
python src/verify_balancing.py
```
Validates:
1. `[PASS]` Dataset loaded (`feature_engineered_access_logs.csv`).
2. `[PASS]` Target identified (`label` column verified).
3. `[PASS]` Class distribution calculated across all 6 classes.
4. `[PASS]` Train/test split completed (80% train = 1,193,745, 20% test = 298,437).
5. `[PASS]` Test set remained untouched (retains true 9,298:1 operational imbalance).
6. `[PASS]` Random undersampling completed (768 balanced records).
7. `[PASS]` Random oversampling completed (60,000 balanced records).
8. `[PASS]` SMOTE completed (60,000 synthetic balanced records).
9. `[PASS]` No target leakage (feature matrix $X$ strictly isolated from target labels).
10. `[PASS]` No NaN values in final ML matrix (0 missing values).
11. `[PASS]` No infinite values (0 infs).
12. `[PASS]` Final balanced dataset saved (`balanced_training_dataset.csv`).
13. `[PASS]` Test dataset saved (`test_dataset.csv`).
14. `[PASS]` Class distribution improved (imbalance ratio reduced from 9,298:1 to 1.0:1).

---

## 7. Viva Voce Questions & Answers

**Q1: Why is class imbalance particularly dangerous in cybersecurity intrusion detection?**  
*Answer:* In honeypot telemetry, benign traffic accounts for 99.71% of all activity. If a model predicts "benign" for 100% of requests, it achieves a deceptively high nominal accuracy of 99.71%. However, its recall on attacks is 0%, allowing 100% of malicious intrusions (SQL injections, brute force attacks, web shells) to penetrate undetected. Balancing ensures that learning algorithms penalize misclassifications on minority attack classes equally.

**Q2: Why must class balancing NEVER be performed before the train/test split?**  
*Answer:* If balancing techniques (such as SMOTE or Random Oversampling) are applied to the entire dataset before splitting, synthetic samples derived from test observations or exact duplicate rows will leak into both training and testing folds. This constitutes severe data leakage: the model is evaluated on data it was trained on, yielding artificially inflated test metrics that collapse in production. The test set must remain untouched and reflect true real-world operational distributions.

**Q3: How does SMOTE synthesize new data points, and why is it superior to Random Oversampling?**  
*Answer:* Random Oversampling duplicates existing samples with replacement. This creates multiple identical copies of minority records, which artificially narrows decision boundaries and causes complex models (such as Gradient Boosted Trees or Deep Neural Networks) to overfit. SMOTE selects a minority instance $x_i$, finds its $k$-nearest neighbors belonging to the same class in feature space, randomly selects one neighbor $x_{zi}$, and generates a new instance along the line segment joining them: $x_{new} = x_i + \lambda (x_{zi} - x_i)$ where $\lambda \in [0, 1]$. This expands minority class variance without duplicating records.

**Q4: What are the primary drawbacks of Random Undersampling?**  
*Answer:* While Random Undersampling is computationally trivial and equalizes class frequencies, its primary flaw in severely imbalanced datasets (e.g., 9,298:1) is extreme information loss. To match the 128 training instances of SQL injection, undersampling discards over 1,190,000 benign requests, throwing away 99.98% of benign traffic patterns and increasing false-positive rates when confronted with normal traffic variety.

**Q5: Why is evaluation on an untouched, imbalanced test set still valid if the training set was balanced?**  
*Answer:* The objective of balancing is solely to facilitate model parameter convergence during optimization by providing balanced gradient updates. However, model deployment occurs in an imbalanced real-world environment. Therefore, evaluating on the untouched imbalanced test set using threshold-independent metrics (such as Precision-Recall AUC, Balanced Accuracy, and F1-macro) accurately measures the classifier's operational effectiveness under real-world traffic conditions.
