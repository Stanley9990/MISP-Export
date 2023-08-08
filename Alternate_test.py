import configparser
from pymisp import PyMISP

# Read configuration from config.ini file
config = configparser.ConfigParser()
config.read('config.ini')

misp_url = config.get('misp', 'url')
misp_key = config.get('misp', 'key')
misp_verifycert = config.getboolean('misp', 'verifycert')

misp = PyMISP(misp_url, misp_key, misp_verifycert)



attributes = misp.search(controller='attributes', publish_timestamp='1d', type_attribute='ip-src', pythonify=True)

for attribute in attributes:
    print(attribute.event_id, attribute)
