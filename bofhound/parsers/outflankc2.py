import re
import codecs
import json
from datetime import datetime, timezone

from bofhound.logger import logger
from bofhound.parsers.generic_parser import GenericParser
from bofhound.parsers.ldap_search_bof import LdapSearchBofParser

# --- Helper Function for Date Conversion ---
def reconad_time_to_win_timestamp(date_str):
    if not isinstance(date_str, str) or "No value" in date_str or not date_str.strip():
        return "0"
    try:
        if "1/1/1601" in date_str:
            return "0"
        dt_obj = datetime.strptime(date_str.strip(), '%m/%d/%Y %I:%M:%S %p')
        dt_obj = dt_obj.replace(tzinfo=timezone.utc)
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        delta = dt_obj - epoch
        windows_timestamp = int(delta.total_seconds() * 10_000_000)
        return str(windows_timestamp)
    except ValueError:
        return "0"


class OutflankC2JsonParser(LdapSearchBofParser):
    BOF_NAMES = ['ldapsearch', 'reconad', 'reconad-users', 'reconad-computers', 'reconad-groups']

    @staticmethod
    def prep_file(file):
        with codecs.open(file, 'r', 'utf-8') as f:
            return f.read()

    @staticmethod
    def _parse_reconad(response_text):
        parsed_objects = []
        current_object = {}
        previous_attr = None
        in_result_region = False
        
        TIMESTAMP_KEYS = [
            'whencreated', 'whenchanged', 'lastlogon', 'lastlogontimestamp',
            'pwdlastset', 'badpasswordtime', 'dscorepropagationdata'
        ]
        
        IGNORE_STRINGS = [
            "No value set.",
            "Value of type Octet String. No Conversion.",
            "Never Expires.",
            "Unknown type 27."
        ]

        for line in response_text.splitlines():
            if line.strip().startswith('--------------------------------------------------------------------'):
                if current_object:
                    parsed_objects.append(current_object)
                current_object = {}
                in_result_region = True
                previous_attr = None
                continue

            if not in_result_region or not line.strip():
                continue

            match = re.match(r'\[\+\]\s(.*?):(.*)', line)
            if match:
                previous_attr = match.group(1).strip().lower()
                value = match.group(2).strip()
                current_object[previous_attr] = [value] if value else []
            elif re.match(r'^\s{4}', line) and previous_attr in current_object:
                current_object[previous_attr].append(line.strip())

        if current_object:
            parsed_objects.append(current_object)

        # --- DEDICATED ENRICHMENT PASS ---
        # This pass adds special keys required by bofhound's classifiers.
        for obj in parsed_objects:
            obj_classes = [c.lower() for c in obj.get('objectclass', [])]
            
            # Add 'trusts' key for Domain objects
            if 'domain' in obj_classes:
                obj['trusts'] = []
            
            # Add 'ou' key for Organizational Units
            if 'organizationalunit' in obj_classes and 'distinguishedname' in obj:
                dn_val = obj['distinguishedname']
                if isinstance(dn_val, list) and len(dn_val) > 0:
                    obj['ou'] = dn_val[0]
                elif isinstance(dn_val, str):
                    obj['ou'] = dn_val

        # --- FINAL FORMATTING PASS ---
        for obj in parsed_objects:
            keys_to_delete = []
            for key, values in list(obj.items()):
                # Clean the values list first
                values = [v for v in values if v not in IGNORE_STRINGS and v]

                if not values:
                    keys_to_delete.append(key)
                    continue
                
                if key in TIMESTAMP_KEYS:
                    obj[key] = [reconad_time_to_win_timestamp(v) for v in values]
                else:
                    obj[key] = values
                
                if key == 'objectclass':
                    obj[key] = [v.lower() for v in obj.get(key, [])]
                    continue

                if key == 'gplink' and isinstance(obj.get(key), list):
                    cleaned_links = []
                    for link_line in obj[key]:
                        found_links = re.findall(r'(\[LDAP:.*?\])', link_line)
                        for link in found_links:
                            cleaned_links.append(link.strip('[]'))
                    obj[key] = cleaned_links
                    continue

                if key in ['serviceprincipalname', 'memberof', 'member'] and isinstance(obj.get(key), list):
                    obj[key] = ','.join(obj[key])
                    continue

                if isinstance(obj.get(key), list) and len(obj[key]) == 1:
                    obj[key] = obj[key][0]
            
            for key in keys_to_delete:
                del obj[key]
                    
        return parsed_objects

    @staticmethod
    def _parse_ldapsearch(response_text):
        logger.debug("ldapsearch parsing needs to be re-integrated if required.")
        return []

    @staticmethod
    def parse_data(contents):
        all_parsed_objects = []
        for line in contents.splitlines():
            try:
                event_json = json.loads(line.split('UTC ', 1)[1])
                task = event_json.get('task', {})
                task_name = task.get('name', '').lower()
                response_text = task.get('response')
                is_target_bof = any(bof_name in task_name for bof_name in OutflankC2JsonParser.BOF_NAMES)

                if event_json.get('event_type') == 'task_response' and response_text and is_target_bof:
                    if 'reconad' in task_name:
                        all_parsed_objects.extend(OutflankC2JsonParser._parse_reconad(response_text))
                    elif task_name == 'ldapsearch':
                        all_parsed_objects.extend(OutflankC2JsonParser._parse_ldapsearch(response_text))
            except (IndexError, json.JSONDecodeError):
                continue
        return all_parsed_objects

    @staticmethod
    def parse_local_objects(file):
        return GenericParser.parse_file(file, is_outflankc2=True)