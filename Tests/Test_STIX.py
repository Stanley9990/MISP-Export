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


    events_stix = misp.search(controller='attributes', publish_timestamp='1d', pythonify=False, return_format="stix")
    print(events_stix)
    
if __name__ == "__main__":
    main()