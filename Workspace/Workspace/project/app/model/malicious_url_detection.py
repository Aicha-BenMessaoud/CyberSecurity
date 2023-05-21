import requests

def malicious_url_probability(url):
    """
    Takes a URL as input and returns the probability that the URL is a phishing site.
    """
    # Replace YOUR_API_KEY with your actual VirusTotal API key
    api_key = '0b7998a0f881d9dcf72c78041fa0cc2ca11433bd5343f33845e535b2453785f4'
    endpoint = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': api_key, 'resource': url}

    response = requests.get(endpoint, params=params)

    if response.status_code == 200:
        result = response.json()
        if result['response_code'] == 1:
            if result['positives'] > 0:
                # Calculate the probability of how likely the URL is a phishing site
                phishing_score = 1 - (result['positives'] / result['total'])
                return phishing_score
            else:
                return 0.0
        else:
            raise Exception('The URL is not in the VirusTotal database.')
    else:
        raise Exception('Error: {} {}'.format(response.status_code, response.reason))

