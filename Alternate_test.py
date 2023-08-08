import configparser
from pymisp import PyMISP

# Read configuration from config.ini file
config = configparser.ConfigParser()
config.read('config.ini')

misp_url = config.get('misp', 'url')
misp_key = config.get('misp', 'key')
misp_verifycert = config.getboolean('misp', 'verifycert')

misp = PyMISP(misp_url, misp_key, misp_verifycert)

# Search for attributes of type ip-src
ip_src_events = misp.search(controller='attributes', type_attribute='ip-src', to_ids=True)

# Extract and print IP source addresses
for event in ip_src_events:
    for attribute in event['Event']['Attribute']:
        if attribute['type'] == 'ip-src':
            print("IP Source:", attribute['value'])
