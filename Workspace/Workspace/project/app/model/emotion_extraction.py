import pandas as pd
from nrclex import NRCLex
from textblob import TextBlob



def extract_emotions(text):
    sentiment = NRCLex(text) 
    mapping = {'anticip': 'anticipation'}
    emotions = {mapping.get(k, k): v for k, v in sentiment.affect_frequencies.items()}
    return emotions


def extract_emotions_dataframe(text):
    emotions = extract_emotions(text)
    df_emotions = pd.DataFrame([emotions]).applymap(lambda x: int(x > 0))
    df_text = pd.DataFrame({"Text": [text]})
    df = pd.concat([df_text, df_emotions], axis=1)
    return df

# Define a function to get sentiment polarity of each text
def get_sentiment(text):
    blob = TextBlob(text)
    return blob.sentiment.polarity


