"""evaluator.py
Parts 8, 9, 10, 11, 12, 14: Comprehensive Model Evaluation, Visualization & Metrics Export
"""

from typing import Dict, Any, List
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
)

from src.config import (
    LR_METRICS_CSV,
    RF_METRICS_CSV,
    MODEL_COMPARISON_CSV,
    RF_FEATURE_IMPORTANCE_CSV,
    LR_CONFUSION_MATRIX_PNG,
    RF_CONFUSION_MATRIX_PNG,
    MODEL_ACCURACY_COMPARISON_PNG,
    RF_TOP20_FEATURES_PNG,
    CLASS_DISTRIBUTION_PNG,
    LR_REPORT_TXT,
    RF_REPORT_TXT,
)


def evaluate_models(
    y_test: pd.Series,
    y_pred_lr: np.ndarray,
    y_pred_rf: np.ndarray,
    rf_model: Any,
    feature_names: List[str],
    split_meta: Dict[str, Any],
) -> Dict[str, Any]:
    """Computes all metrics, generates confusion matrices, comparative dataframes,

    feature importances, and diagnostic visualizations.
    """
    print("\n" + "=" * 60)
    print("PARTS 8 - 12: MODEL EVALUATION & METRIC SYNTHESIS")
    print("=" * 60)

    classes = sorted(list(np.unique(y_test)))

    # 1. Metric Calculations for Logistic Regression
    acc_lr = float(accuracy_score(y_test, y_pred_lr))
    p_macro_lr, r_macro_lr, f1_macro_lr, _ = precision_recall_fscore_support(
        y_test, y_pred_lr, average="macro", zero_division=0
    )
    p_weight_lr, r_weight_lr, f1_weight_lr, _ = precision_recall_fscore_support(
        y_test, y_pred_lr, average="weighted", zero_division=0
    )
    cm_lr = confusion_matrix(y_test, y_pred_lr, labels=classes)
    report_dict_lr = classification_report(
        y_test, y_pred_lr, labels=classes, output_dict=True, zero_division=0
    )
    report_text_lr = classification_report(
        y_test, y_pred_lr, labels=classes, zero_division=0
    )

    # 2. Metric Calculations for Random Forest
    acc_rf = float(accuracy_score(y_test, y_pred_rf))
    p_macro_rf, r_macro_rf, f1_macro_rf, _ = precision_recall_fscore_support(
        y_test, y_pred_rf, average="macro", zero_division=0
    )
    p_weight_rf, r_weight_rf, f1_weight_rf, _ = precision_recall_fscore_support(
        y_test, y_pred_rf, average="weighted", zero_division=0
    )
    cm_rf = confusion_matrix(y_test, y_pred_rf, labels=classes)
    report_dict_rf = classification_report(
        y_test, y_pred_rf, labels=classes, output_dict=True, zero_division=0
    )
    report_text_rf = classification_report(
        y_test, y_pred_rf, labels=classes, zero_division=0
    )

    # 3. Export Part 9 Metrics CSVs
    df_metrics_lr = pd.DataFrame(report_dict_lr).transpose()
    df_metrics_lr.to_csv(LR_METRICS_CSV, index=True)
    print(f"Saved Logistic Regression metrics to:\n  -> {LR_METRICS_CSV}")

    df_metrics_rf = pd.DataFrame(report_dict_rf).transpose()
    df_metrics_rf.to_csv(RF_METRICS_CSV, index=True)
    print(f"Saved Random Forest metrics to:\n  -> {RF_METRICS_CSV}")

    # 4. Export Part 10 Model Comparison Table
    comparison_data = [
        {
            "Model": "Logistic Regression",
            "Accuracy": acc_lr,
            "Macro Precision": float(p_macro_lr),
            "Macro Recall": float(r_macro_lr),
            "Macro F1": float(f1_macro_lr),
            "Weighted Precision": float(p_weight_lr),
            "Weighted Recall": float(r_weight_lr),
            "Weighted F1": float(f1_weight_lr),
        },
        {
            "Model": "Random Forest",
            "Accuracy": acc_rf,
            "Macro Precision": float(p_macro_rf),
            "Macro Recall": float(r_macro_rf),
            "Macro F1": float(f1_macro_rf),
            "Weighted Precision": float(p_weight_rf),
            "Weighted Recall": float(r_weight_rf),
            "Weighted F1": float(f1_weight_rf),
        },
    ]
    df_comparison = pd.DataFrame(comparison_data)
    df_comparison.to_csv(MODEL_COMPARISON_CSV, index=False)
    print(f"Saved Model Comparison to:\n  -> {MODEL_COMPARISON_CSV}")

    # 5. Part 11: Random Forest Feature Importance
    if hasattr(rf_model, "feature_importances_"):
        importances = rf_model.feature_importances_
        fi_df = pd.DataFrame(
            {"Feature": feature_names, "Importance": importances}
        ).sort_values("Importance", ascending=False)
        fi_df.to_csv(RF_FEATURE_IMPORTANCE_CSV, index=False)
        print(f"Saved Random Forest Feature Importance to:\n  -> {RF_FEATURE_IMPORTANCE_CSV}")

        # Top 20 Plot
        top20 = fi_df.head(20).sort_values("Importance", ascending=True)
        plt.figure(figsize=(10, 7), dpi=300)
        plt.barh(top20["Feature"], top20["Importance"], color="#2563eb", edgecolor="#1e3a8a")
        plt.title("Random Forest — Top 20 Feature Importances", fontsize=12, fontweight="bold", pad=12)
        plt.xlabel("Gini Importance Score", fontsize=10, labelpad=8)
        plt.ylabel("Feature Name", fontsize=10, labelpad=8)
        plt.grid(True, linestyle="--", alpha=0.5, axis="x")
        plt.tight_layout()
        plt.savefig(RF_TOP20_FEATURES_PNG)
        plt.close()
        print(f"Saved Top 20 Feature Importance plot to:\n  -> {RF_TOP20_FEATURES_PNG}")
    else:
        fi_df = pd.DataFrame()

    # 6. Part 8 & 14: Confusion Matrix Plots
    # Logistic Regression
    fig, ax = plt.subplots(figsize=(8, 6.5), dpi=300)
    disp_lr = ConfusionMatrixDisplay(confusion_matrix=cm_lr, display_labels=classes)
    disp_lr.plot(ax=ax, cmap="Blues", colorbar=True, xticks_rotation=45)
    plt.title("Logistic Regression — Multiclass Confusion Matrix", fontsize=12, fontweight="bold", pad=12)
    plt.tight_layout()
    plt.savefig(LR_CONFUSION_MATRIX_PNG)
    plt.close()
    print(f"Saved Logistic Regression Confusion Matrix to:\n  -> {LR_CONFUSION_MATRIX_PNG}")

    # Random Forest
    fig, ax = plt.subplots(figsize=(8, 6.5), dpi=300)
    disp_rf = ConfusionMatrixDisplay(confusion_matrix=cm_rf, display_labels=classes)
    disp_rf.plot(ax=ax, cmap="Greens", colorbar=True, xticks_rotation=45)
    plt.title("Random Forest — Multiclass Confusion Matrix", fontsize=12, fontweight="bold", pad=12)
    plt.tight_layout()
    plt.savefig(RF_CONFUSION_MATRIX_PNG)
    plt.close()
    print(f"Saved Random Forest Confusion Matrix to:\n  -> {RF_CONFUSION_MATRIX_PNG}")

    # 7. Part 12: Model Accuracy and Macro F1 Comparison Bar Chart
    plt.figure(figsize=(8, 5), dpi=300)
    models = ["Logistic Regression", "Random Forest"]
    accuracies = [acc_lr * 100, acc_rf * 100]
    macro_f1s = [f1_macro_lr * 100, f1_macro_rf * 100]

    x = np.arange(len(models))
    width = 0.35

    rects1 = plt.bar(x - width / 2, accuracies, width, label="Accuracy (%)", color="#3b82f6", edgecolor="#1d4ed8")
    rects2 = plt.bar(x + width / 2, macro_f1s, width, label="Macro F1 (%)", color="#10b981", edgecolor="#047857")

    plt.ylabel("Score (%)", fontsize=10, fontweight="bold")
    plt.title("Model Performance: Accuracy vs Macro F1 Score", fontsize=12, fontweight="bold", pad=12)
    plt.xticks(x, models, fontsize=10, fontweight="bold")
    plt.ylim(0, 115)
    plt.legend(loc="upper left")
    plt.grid(True, linestyle="--", alpha=0.5, axis="y")

    # Add text labels on bars
    for rect in rects1:
        h = rect.get_height()
        plt.text(rect.get_x() + rect.get_width() / 2.0, h + 1.5, f"{h:.2f}%", ha="center", va="bottom", fontsize=9, fontweight="bold")
    for rect in rects2:
        h = rect.get_height()
        plt.text(rect.get_x() + rect.get_width() / 2.0, h + 1.5, f"{h:.2f}%", ha="center", va="bottom", fontsize=9, fontweight="bold")

    plt.tight_layout()
    plt.savefig(MODEL_ACCURACY_COMPARISON_PNG)
    plt.close()
    print(f"Saved Accuracy vs Macro F1 comparison plot to:\n  -> {MODEL_ACCURACY_COMPARISON_PNG}")

    # 8. Part 14: Class Distribution Plot
    plt.figure(figsize=(9, 5), dpi=300)
    train_dist = split_meta["train_dist"]
    test_dist = split_meta["test_dist"]
    cls_labels = list(train_dist.keys())

    x_cls = np.arange(len(cls_labels))
    w = 0.35
    plt.bar(x_cls - w / 2, [train_dist[c] for c in cls_labels], w, label="Train Set (80%)", color="#6366f1", edgecolor="#4338ca")
    plt.bar(x_cls + w / 2, [test_dist[c] for c in cls_labels], w, label="Test Set (20%)", color="#f59e0b", edgecolor="#b45309")
    plt.yscale("log")
    plt.xlabel("Attack / Traffic Category", fontsize=10, fontweight="bold", labelpad=8)
    plt.ylabel("Record Count (Log Scale)", fontsize=10, fontweight="bold", labelpad=8)
    plt.title("Dataset Class Distribution: Stratified Train vs Test Splits", fontsize=12, fontweight="bold", pad=12)
    plt.xticks(x_cls, cls_labels, rotation=30, ha="right", fontsize=9)
    plt.legend()
    plt.grid(True, linestyle="--", alpha=0.5, axis="y")
    plt.tight_layout()
    plt.savefig(CLASS_DISTRIBUTION_PNG)
    plt.close()
    print(f"Saved Class Distribution plot to:\n  -> {CLASS_DISTRIBUTION_PNG}")

    # 9. Save Part 6 & 7 Individual Report Text Files
    with open(LR_REPORT_TXT, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("LOGISTIC REGRESSION EVALUATION REPORT\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Accuracy:           {acc_lr:.6f} ({acc_lr*100:.2f}%)\n")
        f.write(f"Macro Precision:    {p_macro_lr:.6f}\n")
        f.write(f"Macro Recall:       {r_macro_lr:.6f}\n")
        f.write(f"Macro F1-Score:     {f1_macro_lr:.6f}\n")
        f.write(f"Weighted Precision: {p_weight_lr:.6f}\n")
        f.write(f"Weighted Recall:    {r_weight_lr:.6f}\n")
        f.write(f"Weighted F1-Score:  {f1_weight_lr:.6f}\n\n")
        f.write("Classification Report:\n")
        f.write(report_text_lr + "\n\n")
        f.write("Confusion Matrix:\n")
        f.write(str(cm_lr) + "\n")
    print(f"Saved Logistic Regression text report to:\n  -> {LR_REPORT_TXT}")

    with open(RF_REPORT_TXT, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("RANDOM FOREST EVALUATION REPORT\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Accuracy:           {acc_rf:.6f} ({acc_rf*100:.2f}%)\n")
        f.write(f"Macro Precision:    {p_macro_rf:.6f}\n")
        f.write(f"Macro Recall:       {r_macro_rf:.6f}\n")
        f.write(f"Macro F1-Score:     {f1_macro_rf:.6f}\n")
        f.write(f"Weighted Precision: {p_weight_rf:.6f}\n")
        f.write(f"Weighted Recall:    {r_weight_rf:.6f}\n")
        f.write(f"Weighted F1-Score:  {f1_weight_rf:.6f}\n\n")
        f.write("Classification Report:\n")
        f.write(report_text_rf + "\n\n")
        f.write("Confusion Matrix:\n")
        f.write(str(cm_rf) + "\n")
    print(f"Saved Random Forest text report to:\n  -> {RF_REPORT_TXT}")

    eval_results = {
        "classes": classes,
        "lr": {
            "accuracy": acc_lr,
            "macro_precision": p_macro_lr,
            "macro_recall": r_macro_lr,
            "macro_f1": f1_macro_lr,
            "weighted_precision": p_weight_lr,
            "weighted_recall": r_weight_lr,
            "weighted_f1": f1_weight_lr,
            "confusion_matrix": cm_lr,
            "report_text": report_text_lr,
            "report_dict": report_dict_lr,
        },
        "rf": {
            "accuracy": acc_rf,
            "macro_precision": p_macro_rf,
            "macro_recall": r_macro_rf,
            "macro_f1": f1_macro_rf,
            "weighted_precision": p_weight_rf,
            "weighted_recall": r_weight_rf,
            "weighted_f1": f1_weight_rf,
            "confusion_matrix": cm_rf,
            "report_text": report_text_rf,
            "report_dict": report_dict_rf,
        },
        "comparison_df": df_comparison,
        "feature_importance_df": fi_df,
    }

    return eval_results
