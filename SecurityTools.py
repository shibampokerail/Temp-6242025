#This is the library used by The team for Qualys operations


import requests
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth
import logging
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, as_completed

class QualysAPIError(Exception):
    pass
def log_api_call(func):

    @wraps(func)
    def wrapper(*args, **kwargs):
        args_repr = [repr(a) for a in args[1:]]
        kwargs_repr = [f"{k}={v!r}" for k, v in kwargs.items()]
        signature = ", ".join(args_repr + kwargs_repr)

        logger = logging.getLogger(func.__module__)
        logger.info(f"--> Calling API function: {func.__name__}({signature})")

        try:
            result = func(*args, **kwargs)
            if isinstance(result, tuple):
                logger.info(f"<-- {func.__name__} finished, returning: {result}")
            else:

                logger.info(f"<-- {func.__name__} finished successfully.")
            return result
        except Exception as e:
            logger.error(f"[!!!] EXCEPTION in {func.__name__}: {e}")
            raise e

    return wrapper


class QualysAPI:
    def __init__(self, base_url, username, password):
        if not base_url.startswith('https://'):
            raise ValueError("Base URL must start with https://")
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.headers.update({"X-Requested-With": "Python GUI"})
        self.timeout = 20

    def _request(self, method, endpoint, **kwargs):
        """
        Internal request handler with robust error handling and timeout.
        """
        url = f"{self.base_url}{endpoint}"
        log_url = url
        if 'params' in kwargs and kwargs['params']:
            query_string = '&'.join([f"{k}={v}" for k, v in kwargs['params'].items()])
            log_url = f"{url}?{query_string}"

        logging.info(f"Making {method} request to {log_url}")

        if 'data' in kwargs:
            logging.info(f"--- REQUEST BODY ---\n{kwargs.get('data')}\n----------------------")

        try:
            headers = self.session.headers.copy()
            if 'data' in kwargs:
                headers['Content-Type'] = 'application/xml'

            response = self.session.request(method, url, timeout=self.timeout, headers=headers, **kwargs)

            logging.info(f"Received HTTP Status: {response.status_code}")
            logging.info(f"--- RAW API RESPONSE ---\n{response.text}\n--------------------------")

            if response.status_code != 200:
                if response.status_code == 401:
                    raise QualysAPIError("Authentication Failed (401). Please check your username and password.")

                # Try to parse XML error first
                try:
                    root = ET.fromstring(response.text)
                    msg_node = root.find('.//TEXT') or root.find('.//MESSAGE')
                    if msg_node is not None and msg_node.text is not None:
                        raise QualysAPIError(f"API Error ({response.status_code}): {msg_node.text.strip()}")
                except ET.ParseError:
                    # Fallback for non-XML errors (like the 404 HTML page)
                    raise QualysAPIError(
                        f"HTTP Error {response.status_code}: {response.reason}. The API endpoint may be incorrect.")
            return response

        except requests.exceptions.Timeout:
            raise QualysAPIError(
                f"Connection to {self.base_url} timed out after {self.timeout} seconds. Check network connectivity and the API URL.")
        except requests.exceptions.RequestException as e:
            raise QualysAPIError(
                f"A network error occurred. Please check your connection and the API URL. Details: {e}")

    @log_api_call
    def get_all_qps_assets_for_cache(self, num_threads=10):
        """
        Fetches assets using the modern, multi-threaded QPS search API.
        This builds a cache mapping hostname/IP -> asset details.
        """

        logging.info("--- Starting QPS asset fetch ---")
        qps_search_url = f"{self.base_url}/qps/rest/2.0/search/am/asset"
        limit_per_page = 1000

        def fetch_page(offset):
            payload = f"""<?xml version="1.0" encoding="UTF-8"?>
    <ServiceRequest>
      <preferences>
        <limitResults>{limit_per_page}</limitResults>
        <startFromOffset>{offset}</startFromOffset>
      </preferences>
    </ServiceRequest>"""
            # Using the existing self.session for authentication
            response = self.session.post(qps_search_url, data=payload, headers={'Content-Type': 'application/xml'})
            response.raise_for_status()  # Raise an exception for bad status codes
            return ET.fromstring(response.text).findall('.//Asset')

        # First, find out the total number of assets to calculate pages
        total_assets = 0
        try:
            initial_payload = "<ServiceRequest><filters><Filter><field>id</field><operator>GREATER</operator><value>0</value></Filter></filters></ServiceRequest>"
            initial_response = self.session.post(qps_search_url, data=initial_payload,
                                                 headers={'Content-Type': 'application/xml'})
            initial_response.raise_for_status()
            root = ET.fromstring(initial_response.text)
            count_node = root.find('.//count')
            if count_node is not None:
                total_assets = int(count_node.text)
        except Exception as e:
            logging.error(f"Could not determine total asset count from QPS API: {e}")
            raise QualysAPIError("Failed to get total asset count from QPS API.")

        if total_assets == 0:
            logging.warning("QPS API reports 0 total assets.")
            return {}

        logging.info(f"QPS API reports {total_assets} total assets. Calculating pages...")
        offsets = [1 + i * limit_per_page for i in range((total_assets // limit_per_page) + 1)]

        # This helper extracts the primary key (hostname or IP) for the dictionary
        def extract_key(name):
            if not name: return None
            name = name.strip()
            # If it has a dot and is not a pure IP, it's likely a hostname
            if '.' in name and not name.replace('.', '').isdigit():
                return name.split('.')[0].lower()
            return name.lower()

        # The dictionary caches we will build
        qps_data_cache = {}
        tags_library_cache = {}

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            future_to_offset = {executor.submit(fetch_page, offset): offset for offset in offsets}
            for future in as_completed(future_to_offset):
                offset = future_to_offset[future]
                try:
                    assets_batch = future.result()
                    logging.info(f"QPS Fetch (Offset {offset}): Fetched {len(assets_batch)} assets.")
                    # Process the batch and populate the caches
                    for asset in assets_batch:
                        full_name = self._safe_get_text(asset, 'name', default='(no name)')
                        key = extract_key(full_name)

                        tag_names = []
                        tag_list_node = asset.find('.//tags/list')
                        if tag_list_node is not None:
                            for tag in tag_list_node.findall('TagSimple'):
                                tid = self._safe_get_text(tag, 'id')
                                tname = self._safe_get_text(tag, 'name')
                                if tname != 'N/A':
                                    tags_library_cache[tname] = tid
                                    tag_names.append(tname)

                        if key:
                            qps_data_cache[key] = {
                                'id': self._safe_get_text(asset, 'id'),
                                'fullname': full_name,
                                'tags': tag_names
                            }
                except Exception as e:
                    logging.error(f"QPS Fetch (Offset {offset}): Error processing batch - {e}")

        logging.info(
            f"QPS cache build complete. Collected {len(qps_data_cache)} assets and {len(tags_library_cache)} unique tags.")
        return qps_data_cache, tags_library_cache
    @log_api_call
    def test_connection(self):
        """
        Tests the API connection and credentials using a reliable, universal endpoint.
        """
        try:
            self._request("GET", "/api/2.0/fo/asset/group/?action=list&truncation_limit=1")
            return True, "Connection Successful. Ready."
        except QualysAPIError as e:
            return False, str(e)

    def _safe_get_text(self, element, path, default="N/A"):
        """Safely finds a sub-element and returns its text, or a default value."""
        node = element.find(path)
        return node.text if node is not None and node.text is not None else default


    @log_api_call
    def query_assets(self, criteria=None, search_by='ip'):
        """
        Queries for assets using the v2 API.

        :param criteria: The search term (e.g., an IP, a hostname, or None).
        :param search_by: The type of search. Can be 'ip', 'hostname', or 'all'.
        :return: A list of asset dictionaries.
        """
        endpoint = "/api/2.0/fo/asset/host/?action=list"
        params = {
            "details": "All"
        }

        if criteria:
            if search_by == 'ip':
                params["ips"] = criteria
                logging.info(f"Querying for assets with IP matching '{criteria}'")
            elif search_by == 'hostname':
                params["hostnames"] = criteria
                logging.info(f"Querying for assets with hostname matching '{criteria}'")
        else:
            logging.info("Querying for the first batch of all assets.")
            params["truncation_limit"] = 100

        response = self._request("GET", endpoint, params=params)
        root = ET.fromstring(response.content)

        response_node = root.find('.//RESPONSE')
        if response_node is not None:
            code = self._safe_get_text(response_node, 'CODE', default=None)
            if code is not None:
                error_text = self._safe_get_text(response_node, 'TEXT', default="Unknown API Error")
                raise QualysAPIError(f"API Error: {error_text}")

        assets = []
        for host in root.findall('.//HOST'):
            asset = {
                'id': self._safe_get_text(host, 'ID'),
                'ip': self._safe_get_text(host, 'IP'),
                'dns': self._safe_get_text(host, 'DNS'),
                'os': self._safe_get_text(host, 'OS'),
                'tags': ', '.join(
                    self._safe_get_text(t, 'NAME', default='') for t in host.findall('.//TAGS/TAG')
                )
            }
            assets.append(asset)

        if not assets and criteria:
            logging.warning(f"No assets found matching criteria: {criteria}")

        return assets

    @log_api_call
    def get_all_assets_for_cache(self):
        """
        Fetches ALL assets from the API and filters out entries that lack
        an IP address, as they are generally not useful for management.
        This method automatically handles pagination.
        """
        all_assets = []
        last_id = None
        fetch_count = 0
        filtered_out_count = 0

        while True:
            endpoint = "/api/2.0/fo/asset/host/?action=list"
            params = {
                "details": "All",
                "show_tags": "1",
                "truncation_limit": 15000
            }

            if last_id:
                params["id_min"] = last_id
                logging.info(f"Paginating: Fetching next batch of assets starting after ID {last_id}")
            else:
                logging.info("Fetching initial batch of assets...")

            response = self._request("GET", endpoint, params=params)
            root = ET.fromstring(response.content)

            response_node = root.find('.//RESPONSE')
            if response_node is not None:
                code = self._safe_get_text(response_node, 'CODE', default=None)
                if code is not None:
                    error_text = self._safe_get_text(response_node, 'TEXT', default="Unknown API Error")
                    raise QualysAPIError(f"API Error: {error_text}")

            batch_assets = []
            host_list_node = root.find('.//RESPONSE/HOST_LIST')
            if host_list_node is not None:
                for host in host_list_node.findall('HOST'):
                    ip_address = self._safe_get_text(host, 'IP', default='N/A')
                    hostname = self._safe_get_text(host, 'DNS_DATA/HOSTNAME', default='N/A')
                    tags_list = []
                    tags_node = host.find('TAGS')
                    if tags_node is not None:
                        for tag in tags_node.findall('TAG'):
                            tag_name = self._safe_get_text(tag, 'NAME', default=None)
                            if tag_name:
                                tags_list.append(tag_name)

                    asset = {
                        'id': self._safe_get_text(host, 'ID'),
                        'ip': ip_address,
                        'hostname': hostname,
                        'hostname_lower': hostname.lower(),
                        'tags': tags_list
                    }
                    batch_assets.append(asset)

            if not batch_assets:
                logging.info("Fetched an empty batch. Pagination complete.")
                break

            all_assets.extend(batch_assets)
            fetch_count += len(batch_assets)
            logging.info(f"Fetched {len(batch_assets)} valid assets in this batch. Total so far: {fetch_count}")

            warning_node = root.find('.//RESPONSE/WARNING')
            if warning_node is not None and 'truncated' in self._safe_get_text(warning_node, 'TEXT', '').lower():
                last_id_node = warning_node.find('URL')
                if last_id_node is not None:
                    url_text = last_id_node.text
                    try:
                        last_id = url_text.split('id_min=')[1].split('&')[0]
                    except IndexError:
                        logging.error("Could not parse next id_min from truncation warning URL. Stopping pagination.")
                        break
                else:
                    logging.error("Truncation warning found, but no next URL provided. Stopping pagination.")
                    break
            else:
                logging.info("No truncation warning in response. Pagination complete.")
                break

        logging.info(f"Successfully built cache with a total of {len(all_assets)} assets.")
        if filtered_out_count > 0:
            logging.info(f"Filtered out {filtered_out_count} assets that had no IP address.")

        return all_assets

    @log_api_call
    def get_all_tags_for_cache(self):
        """
        Fetches ALL tags from the API to build a cache for ID lookups.
        """
        return self.query_tags(name=None)

    @log_api_call
    def query_tags(self, name=None):
        endpoint = "/api/2.0/fo/asset/tag/?action=list"
        params = {}
        if name:
            params['name'] = name

        response = self._request("GET", endpoint, params=params)
        root = ET.fromstring(response.content)
        tags = []
        for tag_node in root.findall('.//TAG'):
            tag_data = {
                'id': self._safe_get_text(tag_node, 'ID'),
                'name': self._safe_get_text(tag_node, 'NAME'),
                'created': self._safe_get_text(tag_node, 'CREATED'),
                'modified': self._safe_get_text(tag_node, 'MODIFIED'),
            }
            tags.append(tag_data)
        return tags


    @log_api_call
    def update_asset_tags_by_id(self, asset_id, add_tag_ids, remove_tag_ids):
        """
        Updates tags for a single asset using the /qps/rest/2.0/update/am/asset endpoint.
        This method requires TAG IDs.
        """
        logging.info(f"--- Attempting tag update using Asset Management API for asset ID: {asset_id} ---")
        logging.info(f"  - Tag IDs to Add: {add_tag_ids}")
        logging.info(f"  - Tag IDs to Remove: {remove_tag_ids}")

        endpoint = "/qps/rest/2.0/update/am/asset"

        add_xml_section = ""
        if add_tag_ids:
            add_tags_xml = "".join([f"<TagSimple><id>{tag_id}</id></TagSimple>" for tag_id in add_tag_ids])
            add_xml_section = f"<add>{add_tags_xml}</add>"

        remove_xml_section = ""
        if remove_tag_ids:
            remove_tags_xml = "".join([f"<TagSimple><id>{tag_id}</id></TagSimple>" for tag_id in remove_tag_ids])
            remove_xml_section = f"<remove>{remove_tags_xml}</remove>"

        xml_payload = f"""
<ServiceRequest>
  <data>
    <Asset>
      <id>{asset_id}</id>
      <tags>
        {add_xml_section}
        {remove_xml_section}
      </tags>
    </Asset>
  </data>
</ServiceRequest>
        """.strip()

        response = self._request("POST", endpoint, data=xml_payload)
        root = ET.fromstring(response.content)

        response_code_node = root.find('.//responseCode')
        if response_code_node is not None and response_code_node.text == 'SUCCESS':
            logging.info("API returned SUCCESS for tag update.")
            response_text_node = root.find('.//responseText')
            if response_text_node is not None and response_text_node.text is not None:
                return response_text_node.text
            return "Asset tags updated successfully."
        else:
            # Handle API-level errors
            error_message = "Unknown error during tag update."
            response_text_node = root.find('.//responseText')
            if response_text_node is not None and response_text_node.text is not None:
                error_message = response_text_node.text
            logging.error(f"Tag update failed. API response: {error_message}")
            raise QualysAPIError(error_message)

    @log_api_call
    def bulk_tag_assets_from_csv(self, file_path):
        endpoint = "/api/2.0/fo/asset/tag/?action=update&tag_host_ips=1"
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (f.name, f, 'text/csv')}
                response = self._request("POST", endpoint, files=files)
            root = ET.fromstring(response.content)
            message_node = root.find('.//MESSAGE')
            if message_node is not None:
                return message_node.text
            else:
                return "Bulk job submitted, but no confirmation message received."
        except FileNotFoundError:
            raise ValueError("CSV file not found at the specified path.")
        except Exception as e:
            raise QualysAPIError(f"Failed to process CSV file: {e}")








