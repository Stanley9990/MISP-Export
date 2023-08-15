import configparser
from pymisp import PyMISP
from stix2 import Bundle, DomainName, IPv4Address, URL

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
 
    # Create a STIX bundle
    stix_bundle = Bundle()

    # Populate STIX bundle with attributes
    for domain in domains:
        stix_bundle.add(DomainName(value=domain))

    for ip in ips:
        stix_bundle.add(IPv4Address(value=ip))

    for url in urls:
        stix_bundle.add(URL(value=url))

    # Export STIX bundle to a file
    with open('export/attributes.stix', 'w') as f:
        f.write(stix_bundle.serialize(pretty=True))


if __name__ == "__main__":
    main()






