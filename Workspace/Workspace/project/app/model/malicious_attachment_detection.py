import requests
def get_malicious_prob_from_content(file_contents):
    # URL to upload the file
    upload_url = "https://www.virustotal.com/api/v3/files"

    # URL to get analysis results
    analysis_url = "https://www.virustotal.com/api/v3/analyses/"

    # API key
    api_key = "96893c6697cf422304f1edccf5a3019744bb9eddd7bd2d356f1499171ce4a893"

    # Headers for all requests
    headers = {"x-apikey": api_key}

    # Upload the file
    files = {"file": file_contents}
    response = requests.post(upload_url, headers=headers, files=files)

    # Extract the analysis ID from the response
    analysis_id = response.json()["data"]["id"]

    # Analyze the file
    params = {"include": "stats"}
    analysis_url += analysis_id
    response = requests.get(analysis_url, headers=headers, params=params)

    # Get the analysis results
    stats = response.json()["data"]["attributes"]["stats"]
    malicious_engines = stats["malicious"]
    total_engines = stats["malicious"] + stats["undetected"] + stats["suspicious"] + stats["harmless"]
    if total_engines == 0:
        return 0.0
    else:
        malicious_prob = malicious_engines / total_engines
        return malicious_prob

