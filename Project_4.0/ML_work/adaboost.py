from sklearn.feature_extraction.text import CountVectorizer
from sklearn.ensemble import AdaBoostClassifier, RandomForestClassifier
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import StratifiedKFold
from sklearn.model_selection import StratifiedShuffleSplit
from imblearn.over_sampling import RandomOverSampler
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
# Perform k-fold cross validation
# Perform stratified k-fold cross validation
# Perform random oversampling


# Load data from CSV file
data = pd.read_csv('df_m.csv')

# Define the input and output columns
texts = data['text']
labels = data['majority']

# Extract features from the text data using a CountVectorizer
oversampler = RandomOverSampler()
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(texts)

# Split the data into training and test sets
#X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.2, random_state=42)


# Train a classifier using the training data
X_resampled, y_resampled = oversampler.fit_resample(X, labels)
classifier = AdaBoostClassifier(n_estimators=100)
classifier.fit(X_resampled, y_resampled)

# Perform k-fold cross validation
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
scores = cross_val_score(classifier, X_resampled, y_resampled, cv=skf)

# Print accuracy results for each fold
for i, score in enumerate(scores):
    print(f"Accuracy for fold {i+1}: {score}")

# Calculate and print the mean accuracy across all folds
mean_accuracy = scores.mean()
print("Mean Accuracy:", mean_accuracy)