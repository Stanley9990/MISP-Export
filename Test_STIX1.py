import configparser
from pymisp import PyMISP
from stix.core import STIXPackage
from stix.indicator import Indicator
from stix.common import InformationSource
from stix.utils import set_id_namespace


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

    # Set STIX 1.1 namespace
    set_id_namespace("http://stix.mitre.org/stix-1")

    # Add Information Source
    information_source = InformationSource()
    information_source.identity = "MISP"
    stix_package.stix_header.information_source = information_source

    # Create Indicator types for normalized IOCs
    for ioc in normalized_iocs:
        indicator = Indicator()
        indicator.title = ioc
        stix_package.add_indicator(indicator)

    # Export STIX Package to a file
    with open('export/attributes.stix', 'wb') as f:  # Open the file in binary write mode
        f.write(stix_package.to_xml())  # Decode bytes to string and write to the file


if __name__ == "__main__":
    main()
