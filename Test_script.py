import configparser
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
        attributes = misp.search(controller='attributes', publish_timestamp='1d', type_attribute=common_name, pythonify=True)
        for attribute in attributes:
            if attribute.to_ids is True:
                print(f"Attribute {attribute.value} is flagged IDS:TRUE ({attribute.to_ids})")
            elif attribute.to_ids is False:
                print(f"Attribute {attribute.value} is flagged IDS:FALSE ({attribute.to_ids})")
            else:
                print("Error - to_ids sect")

    for common_name in domain_common_names:
        print(f"Current Attribute is {common_name}")
        attributes = misp.search(controller='attributes', publish_timestamp='1d', type_attribute=common_name, pythonify=True)
        for attribute in attributes:
            if attribute.to_ids is True:
                print(f"Attribute {attribute.value} is flagged IDS:TRUE ({attribute.to_ids})")
            elif attribute.to_ids is False:
                print(f"Attribute {attribute.value} is flagged IDS:FALSE ({attribute.to_ids})")
            else:
                print("Error - to_ids sect")    

    for common_name in url_common_names:
        print(f"Current Attribute is {common_name}")
        attributes = misp.search(controller='attributes', publish_timestamp='1d', type_attribute=common_name, pythonify=True)
        for attribute in attributes:
            if attribute.to_ids is True:
                print(f"Attribute {attribute.value} is flagged IDS:TRUE ({attribute.to_ids})")
            elif attribute.to_ids is False:
                print(f"Attribute {attribute.value} is flagged IDS:FALSE ({attribute.to_ids})")
            else:
                print("Error - to_ids sect")


if __name__ == "__main__":
    main()