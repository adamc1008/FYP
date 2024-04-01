from sklearn.feature_extraction.text import CountVectorizer
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import StratifiedKFold
from sklearn.model_selection import StratifiedShuffleSplit
from imblearn.over_sampling import RandomOverSampler
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from imblearn.under_sampling import RandomUnderSampler
# Perform k-fold cross validation
# Perform stratified k-fold cross validation
# Perform random oversampling


# Load data from CSV file
data = pd.read_csv('df_m.csv')

# Define the input and output columns
texts = data['text']
labels = data['majority']

# Extract features from the text data using a CountVectorizer
oversampler = RandomUnderSampler()
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(texts)

# Split the data into training and test sets
#X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.2, random_state=42)


# Train a classifier using the training data
classifier = MLPClassifier(hidden_layer_sizes=(10, 5),random_state=43, early_stopping=True)
X_resampled, y_resampled = oversampler.fit_resample(X, labels)
classifier.fit(X_resampled, y_resampled)

# Perform k-fold cross validation
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
scores = cross_val_score(classifier, X_resampled, y_resampled, cv=skf)

# Print accuracy results for each fold
for i, score in enumerate(scores):
    print(f"Accuracy for fold {i+1}: {score}")

print("Classification Report for Test Data:")
print(classification_report(y_test_encoded, y_pred))

joblib.dump(classifier, 'random_forest.pkl')
joblib.dump(vectorizer, 'vectorizer_random_forest.pkl')