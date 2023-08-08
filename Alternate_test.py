import configparser
from pymisp import PyMISP

def main():
    # Read configuration from config.ini
    config = configparser.ConfigParser()
    config.read('config.ini')

    misp_url = config['misp']['url']
    misp_key = config['misp']['key']
    verify_cert = config.getboolean('misp', 'verifycert')

    # Initialize PyMISP instance
    misp = PyMISP(misp_url, misp_key, verify_cert, debug=False)

    # Fetch events from MISP instance
    events = misp.search(controller='events')

    for event in events['response']:
        event_id = event['Event']['id']
        attributes = misp.search(controller='attributes', eventid=event_id, type_attribute='ip-src')
        
        for attribute in attributes['response']:
            print(f"Event ID: {event_id}, Attribute: {attribute['Attribute']['value']}")

if __name__ == "__main__":
    main()
