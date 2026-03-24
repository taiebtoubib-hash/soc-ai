"""
Evaluation script for ML models.
"""
from sklearn.metrics import classification_report, confusion_matrix

def evaluate_performance(y_true, y_pred):
    """Print classification report and confusion matrix."""
    print(classification_report(y_true, y_pred))
    print(confusion_matrix(y_true, y_pred))
