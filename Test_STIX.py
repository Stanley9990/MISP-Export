import configparser
from pymisp import PyMISP
import json
from stix2 import Bundle, Indicator
from stix2 import CustomObservable

def main():
    # Read configuration from config.ini file
    config = configparser.ConfigParser()
    config.read('config.ini')

    misp_url = config.get('misp', 'url')
    misp_key = config.get('misp', 'key')
    misp_verifycert = config.getboolean('misp', 'verifycert')

    # Lists to store extracted attributes
    domains = []
    ips = []
    urls = []

    #Define Common Names
    ip_common_names = ['ip-src', 'ip-dst', 'ip', 'ipv4-addr', 'ipv6-addr']
    domain_common_names = ['domain', 'hostname', 'fqdn']
    url_common_names = ['url']

    #MISP connection
    misp = PyMISP(misp_url, misp_key, misp_verifycert)


    #The following 3 For loops iterate through attribute names defined in the lists defined above
    #They will grab all Attributes from the last 1d (One Day) and add them to the exported lists
    #This could probably be turned into a function for elegance, but works for now

    for common_name in ip_common_names:
        attributes = misp.search(controller='attributes', publish_timestamp='1d', type_attribute=common_name, pythonify=True)
        for attribute in attributes:
            if attribute.to_ids is True:
                ips.append(attribute.value)
            elif attribute.to_ids is False:
                print("Non IDS Attribute")
            else:
                print("Error Occured")

    for common_name in domain_common_names:
        attributes = misp.search(controller='attributes', publish_timestamp='1d', type_attribute=common_name, pythonify=True)
        for attribute in attributes:
            if attribute.to_ids is True:
                domains.append(attribute.value)
            elif attribute.to_ids is False:
                print("Non IDS Attribute")
            else:
                print("Error Occured")

    for common_name in url_common_names:
        attributes = misp.search(controller='attributes', publish_timestamp='1d', type_attribute=common_name, pythonify=True)
        for attribute in attributes:
            if attribute.to_ids is True:
                urls.append(attribute.value)
            elif attribute.to_ids is False:
                print("Non IDS Attribute")
            else:
                print("Error Occured")
        # Export domains to a file
    with open('export/domains.txt', 'w') as f:
        f.write('\n'.join(domains))

    # Export IP addresses to a file
    with open('export/ips.txt', 'w') as f:
        f.write('\n'.join(ips))

    # Export URLs to a file
    with open('export/urls.txt', 'w') as f:
        f.write('\n'.join(urls))


    # Read IP addresses from ips.txt
    with open('ips.txt', 'r') as ip_file:
        ips = ip_file.read().splitlines()

    # Read URLs from urls.txt
    with open('urls.txt', 'r') as url_file:
        urls = url_file.read().splitlines()

    # Read domains from domains.txt
    with open('domains.txt', 'r') as domain_file:
        domains = domain_file.read().splitlines()

    # Create Indicator objects for IPs, URLs, and Domains
    indicators = []
    for ip in ips:
        indicators.append(Indicator(name=f"IP Indicator: {ip}", pattern=f"[ipv4-addr:value = '{ip}']"))

    for url in urls:
        indicators.append(Indicator(name=f"URL Indicator: {url}", pattern=f"[url:value = '{url}']"))

    for domain in domains:
        indicators.append(Indicator(name=f"Domain Indicator: {domain}", pattern=f"[domain-name:value = '{domain}']"))

    # Create a Bundle to hold the indicators
    bundle = Bundle(objects=indicators)

    # Serialize the Bundle to JSON
    stix_content = bundle.serialize(pretty=True)

    # Write the STIX content to a file
    with open('output.stix', 'w') as stix_file:
        stix_file.write(stix_content)

    print("STIX file created successfully!")

    if __name__ == "__main__":
        main()






