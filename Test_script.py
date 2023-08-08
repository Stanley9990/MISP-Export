import configparser
from pymisp import PyMISP

# Read configuration from config.ini file
config = configparser.ConfigParser()
config.read('config.ini')

misp_url = config.get('misp', 'url')
misp_key = config.get('misp', 'key')
misp_verifycert = config.getboolean('misp', 'verifycert')

# Lists to store extracted data
domains = []
ips = []
urls = []

#Define Common Names
ip_common_names = ['ip-src', 'ip-dst', 'ip', 'ipv4-addr', 'ipv6-addr']
domain_common_names = ['domain', 'hostname', 'fqdn']
url_common_names = ['url','link']

#Define MISP
misp = PyMISP(misp_url, misp_key, misp_verifycert)


# Search for all attributes of type ip-src
attributes = misp.search(controller='attributes', publish_timestamp='1d', type_attribute='ip-src', pythonify=True)

# Append all found attributes to list 
for attribute in attributes:
    print(attribute.value)
    ips.append(attribute.value)

print("ip-src done")


# Export domains to a file
with open('export/domains.txt', 'w') as f:
    f.write('\n'.join(domains))

# Export IP addresses to a file
with open('export/ips.txt', 'w') as f:
    f.write('\n'.join(ips))

# Export URLs to a file
with open('export/urls.txt', 'w') as f:
    f.write('\n'.join(urls))
