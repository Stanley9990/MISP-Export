import requests
from configparser import ConfigParser

# Load configuration from config.ini
config = ConfigParser()
config.read('config.ini')

misp_url = config.get('misp', 'url')
api_key = config.get('misp', 'key')
verify_cert = config.getboolean('misp', 'verifycert')

# Construct the full URL for the download
download_url = f"{misp_url}/attributes/text/download/ip-src"

# Set up the headers with the API key
headers = {
    "Authorization": f"Bearer {api_key}"
}

# Make the request
response = requests.get(download_url, headers=headers, verify=verify_cert)

# Check if the request was successful
if response.status_code == 200:
    # Print the downloaded content
    print(response.text)
else:
    print(f"Request failed with status code: {response.status_code}")
