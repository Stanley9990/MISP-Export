import configparser
import json
from pymisp import PyMISP

def main():
    # Read configuration from config.ini file
    config = configparser.ConfigParser()
    config.read('config.ini')

    misp_url = config.get('misp', 'url')
    misp_key = config.get('misp', 'key')
    misp_verifycert = config.getboolean('misp', 'verifycert')

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
        print(f"Current Attribute is {common_name}")
        attributes_ip = misp.search(controller='attributes', publish_timestamp='1d', type_attribute=common_name, pythonify=True, to_ids=True, return_format="stix2")
        print(attributes_ip)

    for common_name in domain_common_names:
        print(f"Current Attribute is {common_name}")
        attributes_domains = misp.search(controller='attributes', publish_timestamp='1d', type_attribute=common_name, pythonify=True, to_ids=True, return_format="stix2")
        print(attributes_domains)

    for common_name in url_common_names:
        print(f"Current Attribute is {common_name}")
        attributes_urls = misp.search(controller='attributes', publish_timestamp='1d', type_attribute=common_name, pythonify=True, to_ids=True, return_format="stix2")
        print(attributes_urls)

    with open('domains.stix', 'w') as f:
        json.dump(attributes_domains, f)


if __name__ == "__main__":
    main()
