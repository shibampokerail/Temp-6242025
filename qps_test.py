# This program is the test program used to test the QPS API
# Status: In Progress (runs)
# Note To Reviewer: Setup the ENV file first. Refer to line 29 - 33 before running.

import requests
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
import os

MODE = "DEV"

load_lotenv()
QUALYS_USERNAME = ""
PASSWORD = ""

QUALYS_SEARCH_URL = 'https://qualysapi.qualys.com/qps/rest/2.0/search/am/asset'
QUALYS_UPDATE_URL = 'https://qualysapi.qualys.com/qps/rest/2.0/update/am/asset'

LIMIT = 1000
NUM_THREADS = 11


all_data = {}
tags_library = {}

if MODE=="DEV":
    #The username and password will be provided as arguments in the script in the terminal so this will not be requred
    #---------------------Not Required in Prod---------------------------------------!
    QUALYS_USERNAME = os.getenv("USERNAME")#for some weird reason the api returned an error when using an env file so might wanna hardcode the username and password here for the moment
    PASSWORD = os.getenv("PASSWORD")
    #---------------------Not Required in Prod---------------------------------------!
else:
    pass


def fetch_page(offset):
    """Fetch a page of assets starting from the given offset."""
    payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<ServiceRequest>
  <preferences>
    <limitResults>{LIMIT}</limitResults>
    <startFromOffset>{offset}</startFromOffset>
  </preferences>
</ServiceRequest>"""
    headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml'}
    response = requests.post(
        QUALYS_SEARCH_URL, data=payload, headers=headers,
        auth=HTTPBasicAuth(USERNAME, PASSWORD), timeout=30
    )
    response.raise_for_status()
    return ET.fromstring(response.text).findall('.//Asset')


def extract_key(name):
    if not name:
        return None
    name = name.strip()
    if '.' in name and not name.replace('.', '').isdigit():
        return name.split('.')[0].lower()
    if name.replace('.', '').isdigit():
        return name
    return name.lower()


def process_assets(assets):
    """Populate all_data and tags_library from a list of <Asset> elements."""
    for asset in assets:
        asset_id = asset.findtext('id', default='N/A')
        full_name = asset.findtext('name', default='(no name)')
        key = extract_key(full_name)

        tag_names = []
        tag_list = asset.find('.//tags/list')
        if tag_list is not None:
            for tag in tag_list.findall('TagSimple'):
                tid = tag.findtext('id')
                tname = tag.findtext('name')
                if tid and tname:
                    # Update tags_library
                    tags_library.setdefault(tname, set()).add(tid)
                    tag_names.append(tname)

        if key:
            all_data[key] = {
                'id': asset_id,
                'fullname': full_name,
                'tags': tag_names
            }


def update_asset_tag(asset_id, tag_id, action='add'):
    """Add or remove a tag on an asset via Qualys Update API."""
    # Build XML for add/remove
    op = 'add' if action == 'add' else 'remove'
    payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<ServiceRequest>
  <data>
    <Asset>
      <id>{asset_id}</id>
      <tags>
        <{op}>
          <TagSimple>
            <id>{tag_id}</id>
          </TagSimple>
        </{op}>
      </tags>
    </Asset>
  </data>
</ServiceRequest>"""
    headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml'}
    response = requests.post(
        QUALYS_UPDATE_URL, data=payload, headers=headers,
        auth=HTTPBasicAuth(USERNAME, PASSWORD), timeout=30
    )
    response.raise_for_status()
    return response


def main():
    # Threading and getting the vals
    offsets = [1 + i * LIMIT for i in range(NUM_THREADS)]

    with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        futures = {executor.submit(fetch_page, off): off for off in offsets}
        for future in as_completed(futures):
            off = futures[future]
            try:
                assets = future.result()
                print(f"Offset {off}: fetched {len(assets)} assets")
                process_assets(assets)
            except Exception as e:
                print(f"Offset {off}: error ({e}), skipping")

    print(f"\nDone. Collected {len(all_data)} unique assets and {len(tags_library)} unique tags.\n")

    while True:
        a = input(" Search hostname/IP (or type 'exit'): ").strip().lower()
        if a == 'exit':
            break
        asset = all_data.get(a)
        if not asset:
            print("Not found in dataset.")
            continue

        print("\nMatch found:")
        print(f"ID: {asset['id']}, Name: {asset['fullname']}")
        print("Current tags:", asset['tags'] or "(none)")

        action = input("Do you want to add or remove a tag? (add/remove/skip): ").strip().lower()
        if action not in ('add', 'remove'):
            continue

        # Show available tags
        print("\nAvailable tags:")
        for t in sorted(tags_library.keys()):
            print(" -", t)
        chosen = input(f"\nType the tag name to {action}: ").strip()
        if chosen not in tags_library:
            print("Tag not recognized, skipping.")
            continue
        # If multiple IDs, pick one (static tags normally unique)
        tag_id = next(iter(tags_library[chosen]))

        try:
            response = update_asset_tag(asset['id'], tag_id, action=action)
            # Update local state
            if action == 'add':
                asset['tags'].append(chosen)
            else:
                print(response.text)
                asset['tags'].remove(chosen)

            print(f"Successfully {action}ed tag '{chosen}' on asset {asset['id']}.")
        except Exception as e:
            print(f"Failed to {action} tag: {e}")


if __name__ == "__main__":
    main()

