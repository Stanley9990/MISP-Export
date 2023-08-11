# MISP-Export
A simple Python script to export IPs, Domains and URLs from a MISP Instance

## Usage
- Log into `misp` user
- Clone repo `git clone https://github.com/Stanley9990/MISP-Export.git` into `/home/misp`
- Install dependencies `pip3 install -r requirements.txt` or `pip install -r requirements.txt`
- Populate `config.ini`
- Manually test connection with `python3 Export.py`
    - Check files in `/export` are populated

## Adding attribute names
For now the way to add attribute types is to edit the corresponding `X_common_names` list within `Export.py`.

## Known Issues
- Warning errors will be shown when connection to MISP is established. This is because `verifycert` is set to `False` in `config.ini`

## TODO
- Cronjob Setup Documentation
- ~~check if each IOC has to_ids (Is IDS flag true for the attribute (Or Parent Event))~~
- Pass `X_common_names` into the script through `config.ini`
- Improve Logging
    - Num of new IOCs
    - Time Elapsed
    - Errors
    - etc
