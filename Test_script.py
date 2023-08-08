from pymisp import PyMISP

# Replace these with your MISP instance credentials
misp_url = 'https://misp-instance-url'
misp_key = 'your-api-key'
misp_verifycert = False  # Set to True if using SSL/TLS certificate verification
print("Defined Vars")
misp = PyMISP(misp_url, misp_key, misp_verifycert)
print("Defined misp")
# Fetch all events from MISP
events = misp.search(eventinfo='', pythonify=True)
print("Defined Events")
print(events)
# Lists to store extracted data
domains = []
ips = []
urls = []

for event in events:
    for obj in event.objects:
        print(obj)
        if obj.name == 'domain':
            domain_value = obj.get_attributes_by_relation('domain')[0].value
            domains.append(domain_value)

        elif obj.name == 'ip-src' or obj.name == 'ip-dst':
            ip_value = obj.get_attributes_by_relation('ip')[0].value
            ips.append(ip_value)

        elif obj.name == 'url':
            url_value = obj.get_attributes_by_relation('url')[0].value
            urls.append(url_value)

# Export domains to a file
with open('domains.txt', 'w') as f:
    f.write('\n'.join(domains))

# Export IP addresses to a file
with open('ips.txt', 'w') as f:
    f.write('\n'.join(ips))

# Export URLs to a file
with open('urls.txt', 'w') as f:
    f.write('\n'.join(urls))
