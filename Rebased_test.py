import configparser
from pymisp import PyMISP
def main():
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

    for i in ip_common_names:
        print(f"Current Attribute is {i}")
        current_attributes = getAttributes(i,"1d") #Default 1d
        for attribute in current_attributes:
            ips.append(attribute.value)


def getAttributes(attribute_type,published_timestamp):
    attributes = misp.search(controller='attributes', publish_timestamp=published_timestamp, type_attribute=attribute_type, pythonify=True)
    print(f"{attribute_type} done")
    return attribute



def exportToFile():
    # Export domains to a file
    with open('export/domains.txt', 'w') as f:
        f.write('\n'.join(domains))

    # Export IP addresses to a file
    with open('export/ips.txt', 'w') as f:
        f.write('\n'.join(ips))

    # Export URLs to a file
    with open('export/urls.txt', 'w') as f:
        f.write('\n'.join(urls))


if __name__ == "__main__":
    main()






