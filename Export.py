from pymisp import PyMISP, MISPEvent

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
    misp_event = MISPEvent()
    misp_event.load(event)

    # Extract domains
    for obj in misp_event.objects:
        if obj.name == 'domain':
            domains.append(obj.value)

        # Extract IP addresses
        elif obj.name == 'ip-src' or obj.name == 'ip-dst':
            ips.append(obj.value)

        # Extract URLs
        elif obj.name == 'url':
            urls.append(obj.value)

# Export domains to a file
with open('domains.txt', 'w') as f:
    f.write('\n'.join(domains))

# Export IP addresses to a file
with open('ips.txt', 'w') as f:
    f.write('\n'.join(ips))

# Export URLs to a file
with open('urls.txt', 'w') as f:
    f.write('\n'.join(urls))
