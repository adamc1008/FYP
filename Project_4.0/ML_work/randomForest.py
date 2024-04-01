import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from imblearn.over_sampling import RandomOverSampler
from sklearn.metrics import classification_report
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn import tree
import matplotlib.pyplot as plt
from sklearn.datasets import load_iris
from sklearn.tree import export_graphviz
import graphviz
import joblib
from sklearn.linear_model import LogisticRegression
from imblearn.under_sampling import RandomUnderSampler
from sklearn.utils import compute_class_weight
from sklearn.utils import class_weight

# Load data from CSV file
data = pd.read_csv('df_m.csv')

# Define the input and output columns
texts = data['text']
labels = data['majority']

# Extract features from the text data using a CountVectorizer
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(texts)

# Split the data into training and test sets
X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.2, random_state=42)

# Oversample the training data to handle class imbalance
oversampler = RandomUnderSampler()
X_resampled, y_resampled = oversampler.fit_resample(X_train, y_train)

# Encode labels
label_encoder = LabelEncoder()
y_resampled_encoded = label_encoder.fit_transform(y_resampled)
y_test_encoded = label_encoder.transform(y_test)
# Train a support vector machine classifier using the resampled training data


# Train a random forest classifier using the resampled training data
classifier = RandomForestClassifier(class_weight = 'balanced')
classifier.fit(X_resampled, y_resampled_encoded)

# Perform k-fold cross validation
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
scores = cross_val_score(classifier, X_resampled, y_resampled_encoded, cv=skf)

# Print accuracy results for each fold
for i, score in enumerate(scores):
    print(f"Accuracy for fold {i+1}: {score}")
    # Print image of decision tree


# Calculate and print the mean accuracy across all folds
mean_accuracy = scores.mean()
print("Mean Accuracy:", mean_accuracy)

# Generate predictions on the test set
y_pred = classifier.predict(X_test)
y_train_pred = classifier.predict(X_resampled)

print("Classification Report for Training Data:")
print(classification_report(y_resampled_encoded, y_train_pred))

# Print classification report
print("Classification Report for Test Data:")
print(classification_report(y_test_encoded, y_pred))

joblib.dump(classifier, 'random_forest.pkl')
joblib.dump(vectorizer, 'vectorizer_random_forest.pkl')
