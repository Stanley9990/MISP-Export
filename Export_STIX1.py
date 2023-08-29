#!/usr/bin/python3

import configparser
from pymisp import PyMISP
from stix.core import STIXPackage
from stix.indicator import Indicator
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.uri_object import URI



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
 
    
    stix_objects = []

    # Create Indicator types
    for domain in domains:
        domain_obj = DomainName()
        domain_obj.value = domain
        stix_objects.append(domain_obj)

    for url in urls:
        url_obj = URI()
        url_obj.value = url
        stix_objects.append(url_obj)

    for ip in ips:
        ip_obj = Address(category=Address.CAT_IPV4, address_value=ip)
        stix_objects.append(ip_obj)

    stix_package = STIXPackage()

    for stix_object in stix_objects:
        indicator = Indicator()
        indicator.add_object(stix_object)
        stix_package.add_indicator(indicator)

    stix_filename = "/export/stix1.stix"
    with open(stix_filename, "wb") as stix_file:
        stix_file.write(stix_package.to_xml())

if __name__ == "__main__":
    main()






