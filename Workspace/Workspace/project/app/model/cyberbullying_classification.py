
import string
import unicodedata
from bs4 import BeautifulSoup
import re 
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from googleapiclient import discovery
import json


#Trying the cybercullying api

API_KEY = 'AIzaSyD4otRh6Suo--QAuHQqPgpU1wj3wRaThAs'

def get_toxicity_score(text):
    client = discovery.build(
      "commentanalyzer",
      "v1alpha1",
      developerKey=API_KEY,
      discoveryServiceUrl="https://commentanalyzer.googleapis.com/$discovery/rest?version=v1alpha1",
      static_discovery=False,
    )

    analyze_request = {
      'comment': { 'text': text },
      'requestedAttributes': {'TOXICITY': {}}
    }


    response = client.comments().analyze(body=analyze_request).execute()
    toxicity_score = response['attributeScores']['TOXICITY']['summaryScore']['value']
    return toxicity_score

