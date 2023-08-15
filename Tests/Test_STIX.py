import configparser
import json
from pymisp import PyMISP
from pymisp.tools.stix import make_stix_package

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

    events = misp.search(publish_timestamp='1d', pythonify=True, to_ids=True)

    stix_data = make_stix_package(events)
    with open("domains.stix", 'w') as stix_file:
        stix_file.write(stix_data)
    


if __name__ == "__main__":
    main()
