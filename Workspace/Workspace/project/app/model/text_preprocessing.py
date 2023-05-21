import re
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from bs4 import BeautifulSoup
import unicodedata
import string
import joblib
import pandas as pd
import sklearn
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfTransformer

# Import the saved models
phishing_model = joblib.load("C:/Users/Admin/Downloads/phishing_model (1).joblib")
spam_model_xgb = joblib.load("C:/Users/Admin/Downloads/spam_model_xgb (3).joblib")
fake_news_model = joblib.load("C:/Users/Admin/Downloads/fake_news_model (2).joblib")


# Define a function to preprocess the text
def preprocess_text(text):
    # Remove HTML and nbsp encoding
    soup = BeautifulSoup(text, 'html.parser')
    text = soup.get_text()

    # Remove numbers not attached to any other word
    text = re.sub(r'\b\d+\b', '', text)

    # Normalize unicode characters
    text = unicodedata.normalize('NFKD', text).encode('ascii', 'ignore').decode('utf-8', 'ignore')

    # Tokenize the text into words
    tokens = word_tokenize(text.lower())

    # Remove stop words and punctuation
    stop_words = set(stopwords.words('english') + list(string.punctuation))
    filtered_tokens = [token for token in tokens if token not in stop_words]

    # Return list of tokens
    return filtered_tokens

def bag_of_words_phishing_model_vocab(preprocessed_text):
    # Create a CountVectorizer object
    vectorizer = CountVectorizer(vocabulary=phishing_model.get_booster().feature_names)
    
    # Apply BoW to the preprocessed text
    bow_matrix = vectorizer.fit_transform([preprocessed_text])

    # create a DataFrame from the bag of words matrix
    bow_df_phish = pd.DataFrame(bow_matrix.toarray(), columns=phishing_model.get_booster().feature_names)

    return bow_df_phish

def bag_of_words_spam_model_xgb_vocab(preprocessed_text):
    # Create a CountVectorizer object
    vectorizer = CountVectorizer(vocabulary=spam_model_xgb.get_booster().feature_names)
    
    # Apply BoW to the preprocessed text
    bow_matrix = vectorizer.fit_transform([preprocessed_text])

    # create a DataFrame from the bag of words matrix
    bow_df_spam = pd.DataFrame(bow_matrix.toarray(), columns=spam_model_xgb.get_booster().feature_names)

    return bow_df_spam

def bag_of_words_fake_news_model_vocab(preprocessed_text):
    # Create a CountVectorizer object
    vectorizer = CountVectorizer(vocabulary=fake_news_model.get_booster().feature_names)
    
    # Apply BoW to the preprocessed text
    bow_matrix = vectorizer.fit_transform([preprocessed_text])

    # create a DataFrame from the bag of words matrix
    bow_df = pd.DataFrame(bow_matrix.toarray(), columns=fake_news_model.get_booster().feature_names)
    return bow_df






