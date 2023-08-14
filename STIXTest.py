import configparser
from pymisp import PyMISP

def main():
    # Read configuration from config.ini file
    config = configparser.ConfigParser()
    config.read('config.ini')

    misp_url = config.get('misp', 'url')
    misp_key = config.get('misp', 'key')
    misp_verifycert = config.getboolean('misp', 'verifycert')

    # Lists to store extracted attributes
    StixList = []

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
        attributes = misp.search(controller='attributes', publish_timestamp='1d', type_attribute=common_name,return_format='stix2', pythonify=True)
        print(attributes)
        StixList.append(attributes)
    for common_name in domain_common_names:
        attributes = misp.search(controller='attributes', publish_timestamp='1d', type_attribute=common_name, pythonify=True, return_format='stix2')
        print(attributes)
        StixList.append(attributes)
    for common_name in url_common_names:
        attributes = misp.search(controller='attributes', publish_timestamp='1d', type_attribute=common_name,return_format='stix2', pythonify=True)
        print(attributes)
        StixList.append(attributes)
    print(StixList)
    with open('export/test.stix', 'w') as f:
        f.write(StixList)

if __name__ == "__main__":
    main()






