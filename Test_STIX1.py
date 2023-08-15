import configparser
from pymisp import PyMISP
from stix.core import STIXPackage
from stix.indicator import Indicator
from stix.indicator.indicator import IndicatorType


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
 
    
     # Create a STIX Package
    stix_package = STIXPackage()

    # Create Indicator types
    for domain in domains:
        indicator = Indicator()
        indicator.title = domain
        indicator.indicator_types.append(IndicatorType("Domain Name"))
        stix_package.add_indicator(indicator)

    for ip in ips:
        indicator = Indicator()
        indicator.title = ip
        indicator.indicator_types.append(IndicatorType("IPv4"))
        stix_package.add_indicator(indicator)

    for url in urls:
        indicator = Indicator()
        indicator.title = url
        indicator.indicator_types.append(IndicatorType("URL"))
        stix_package.add_indicator(indicator)

    # Export STIX Package to a file
    with open('export/attributes.stix', 'wb') as f:  # Open the file in binary write mode
        f.write(stix_package.to_xml())  # Decode bytes to string and write to the file


if __name__ == "__main__":
    main()
