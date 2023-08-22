# MISP-Export
A collection of simple Python scripts to export IPs, Domains and URLs from a MISP Instance, in either TXT, STIX1 or STIX2 format

## Usage
- Clone repo `git clone https://github.com/Stanley9990/MISP-Export.git`
- Install dependencies `pip3 install -r requirements.txt` or `pip install -r requirements.txt`
- Populate `config.ini`
- Manually test connection with `python3 <ScriptName>`
    - Check files in `/export` are populated

## Adding attribute names
For now the way to add attribute types is to edit the corresponding `X_common_names` list within the scripts

## Known Issues
- Warning errors will be shown when connection to MISP is established. This is because `verifycert` is set to `False` in `config.ini`
- The printed lines in the source of the test script are difficult to read because I have used inline colour codes. Am I going to change this? Probably not.

