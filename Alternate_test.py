import configparser
import requests

# Read configuration from config.ini file
config = configparser.ConfigParser()
config.read('config.ini')

misp_url = config.get('misp', 'url')
misp_key = config.get('misp', 'key')
misp_verifycert = config.getboolean('misp', 'verifycert')

# Define the URLs for attribute files
ip_src_url = f'{misp_url}/attributes/text/download/ip-src'
ip_dst_url = f'{misp_url}/attributes/text/download/ip-dst'
domain_url = f'{misp_url}/attributes/text/download/domain'
hostname_url = f'{misp_url}/attributes/text/download/hostname'
url_url = f'{misp_url}/attributes/text/download/url'

# Headers with API key
headers = {
    'Authorization': f'Bearer {misp_key}'
}

# Function to download and save data to a file
def download_and_save(url, output_file):
    response = requests.get(url, headers=headers, verify=misp_verifycert)
    if response.status_code == 200:
        with open(output_file, 'wb') as f:
            f.write(response.content)
            print(f'Downloaded and saved: {output_file}')
    else:
        print(f'Failed to download: {url}')

# Download IP source and destination addresses
download_and_save(ip_src_url, 'export/ips.txt')
download_and_save(ip_dst_url, 'export/ips.txt')

# Download domains and hostnames
download_and_save(domain_url, 'export/domains.txt')
download_and_save(hostname_url, 'export/domains.txt')

# Download URLs
download_and_save(url_url, 'export/urls.txt')
