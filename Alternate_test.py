import configparser
from pymisp import PyMISP, MISPAttribute

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
    misp_event = MISPAttribute()
    misp_event.load(event)
    print("IP Source:", misp_event.value)
