from pymisp import PyMISP

# Replace these with your MISP instance credentials
misp_url = 'https://misp-instance-url'
misp_key = 'your-api-key'
misp_verifycert = False  # Set to True if using SSL/TLS certificate verification

misp = PyMISP(misp_url, misp_key, misp_verifycert)

# Set your desired confidence threshold (0 to 100)
confidence_threshold = 70

# Fetch all events from MISP
events = misp.search(eventinfo='', pythonify=True)

# Lists to store extracted data
domains = []
ips = []
urls = []

for event in events:
    for obj in event.objects:
        if obj.name == 'domain':
            confidence = obj.ObjectReference[0].confidence if obj.ObjectReference else None
            if confidence is None or (obj.ObjectReference[0].object_relation == 'malicious' and confidence < confidence_threshold):
                continue
            domains.append(obj.value)

        elif obj.name == 'ip-src' or obj.name == 'ip-dst':
            confidence = obj.ObjectReference[0].confidence if obj.ObjectReference else None
            if confidence is None or (obj.ObjectReference[0].object_relation == 'malicious' and confidence < confidence_threshold):
                continue
            ips.append(obj.value)

        elif obj.name == 'url':
            confidence = obj.ObjectReference[0].confidence if obj.ObjectReference else None
            if confidence is None or (obj.ObjectReference[0].object_relation == 'malicious' and confidence < confidence_threshold):
                continue
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
