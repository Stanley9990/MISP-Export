from pymisp import PyMISP

# Replace these with your MISP instance credentials
misp_url = 'https://misp-instance-url'
misp_key = 'your-api-key'
misp_verifycert = False  # Set to True if using SSL/TLS certificate verification

misp = PyMISP(misp_url, misp_key, misp_verifycert)

# Fetch all events from MISP
events = misp.search(eventinfo='', pythonify=True)

# Lists to store extracted data
domains = []
ips = []
urls = []

for event in events:
    for obj in event.objects:
        if obj.name in ['domain','hostname']::
            domain_attribute = obj.attributes[0]
            domains.append(domain_attribute.value)

        elif obj.name in ['ip-src', 'ip-dst']:
            ip_attribute = obj.attributes[0]
            ips.append(ip_attribute.value)

        elif obj.name in ['url','link']:
            url_attribute = obj.attributes[0]
            urls.append(url_attribute.value)

# Export domains to a file
with open('export/domains.txt', 'w') as f:
    f.write('\n'.join(domains))

# Export IP addresses to a file
with open('export/ips.txt', 'w') as f:
    f.write('\n'.join(ips))

# Export URLs to a file
with open('export/urls.txt', 'w') as f:
    f.write('\n'.join(urls))
