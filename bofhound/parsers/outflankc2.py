import re
import codecs
import json

from bofhound.logger import logger
from bofhound.parsers.generic_parser import GenericParser
from bofhound.parsers import LdapSearchBofParser
from bofhound.parsers.recon_ad_parser import ReconAdParser


#
# Parses ldapsearch and ReconAD BOF objects from Outflank C2 JSON logfiles
#   Supports both 'ldapsearch' and 'reconad' BOF commands registered in OC2
#

class OutflankC2JsonParser(LdapSearchBofParser):
    SUPPORTED_BOFS = ['ldapsearch', 'reconad', 'reconad-computers', 'reconad-users', 'reconad-groups']
    

    @staticmethod
    def prep_file(file):
        with codecs.open(file, 'r', 'utf-8') as f:
            return f.read()


    #
    # Slightly modified from LdapSearchBofParser to account for
    #  needing only part of each JSON object, instead of the whole file
    #
    @staticmethod
    def parse_data(contents):
        parsed_objects = []
        current_object = None
        in_result_region = False
        previous_attr = None

        in_result_region = False

        lines = contents.splitlines()
        for line in lines:
            # Handle different timestamp formats in Outflank C2 logs
            if ' UTC ' in line:
                json_part = line.split(' UTC ', 1)[1]
            else:
                # Fallback for lines that might not have UTC timestamp
                continue

            try:
                event_json = json.loads(json_part)
            except json.JSONDecodeError:
                logger.debug(f'Failed to parse JSON from line: {line[:100]}...')
                continue

            # we only care about task_resonse events
            if event_json['event_type'] != 'task_response':
                continue
            
            # within task_response events, we only care about supported BOF tasks
            task_name = event_json['task']['name'].lower()

            # Check if task name matches any supported BOF
            is_supported = False
            for supported_bof in OutflankC2JsonParser.SUPPORTED_BOFS:
                if supported_bof in task_name:
                    is_supported = True
                    break

            if not is_supported:
                continue
            
            # now we have a block of BOF data we can parse through for objects
            response_data = event_json['task']['response']

            # Route to appropriate parser based on BOF type
            if 'reconad' in task_name:
                # Use ReconAD parser for ReconAD BOF output
                bof_objects = OutflankC2JsonParser._parse_reconad_response(response_data)
                parsed_objects.extend(bof_objects)
                continue

            # Default to ldapsearch parsing for 'ldapsearch' BOF
            response_lines = response_data.splitlines()
            for response_line in response_lines:

                is_boundary_line = OutflankC2JsonParser._is_boundary_line(response_line)

                if (not in_result_region and
                    not is_boundary_line):
                    continue

                if (is_boundary_line
                    and is_boundary_line != OutflankC2JsonParser._COMPLETE_BOUNDARY_LINE):
                    while True:
                        try:
                            next_line = next(response_lines)[1]
                            remaining_length = OutflankC2JsonParser._is_boundary_line(next_line, is_boundary_line)

                            if remaining_length:
                                is_boundary_line = remaining_length
                                if is_boundary_line == OutflankC2JsonParser._COMPLETE_BOUNDARY_LINE:
                                    break
                        except:
                            # probably ran past the end of the iterable
                            break

                if (is_boundary_line):
                    if not in_result_region:
                        in_result_region = True
                    elif current_object is not None:
                        # self.store_object(current_object)
                        parsed_objects.append(current_object)
                    current_object = {}
                    continue
                elif re.match("^(R|r)etr(e|i)(e|i)ved \\d+ results?", response_line):
                    #self.store_object(current_object)
                    parsed_objects.append(current_object)
                    in_result_region = False
                    current_object = None
                    continue

                data = response_line.split(': ')

                try:
                    # If we previously encountered a control message, we're probably still in the old property
                    if len(data) == 1:
                        if previous_attr is not None:
                            value = current_object[previous_attr] + response_line
                    else:
                        data = response_line.split(':')
                        attr = data[0].strip().lower()
                        value = ''.join(data[1:]).strip()
                        previous_attr = attr

                    current_object[attr] = value

                except Exception as e:
                    logger.debug(f'Error - {str(e)}')

        return parsed_objects

    @staticmethod
    def _parse_reconad_response(response_data):
        """
        Parse ReconAD BOF output from Outflank C2 JSON response data.

        This method extracts ReconAD formatted output and delegates to
        ReconAdParser for actual parsing.
        """
        try:
            # Clean C2 artifacts from response data (similar to ReconAdParser.prep_file)
            cleaned_data = OutflankC2JsonParser._clean_c2_artifacts(response_data)
            return ReconAdParser.parse_data(cleaned_data)
        except Exception as e:
            logger.debug(f'Error parsing ReconAD response: {str(e)}')
            return []

    @staticmethod
    def _clean_c2_artifacts(data):
        """
        Clean C2 timestamp and output artifacts from ReconAD data.

        This replicates ReconAdParser.prep_file logic for direct data processing.
        """
        # Remove common C2 timestamp and output artifacts
        # Handle both UTC timestamps and "received output:" lines
        data = re.sub(r'\n\n\d{2}\/\d{2} (\d{2}:){2}\d{2} UTC \[output\]\nreceived output:\n', '', data)
        data = re.sub(r'\n\d{2}\/\d{2} (\d{2}:){2}\d{2} UTC \[output\]\n', '', data)
        return data

    #
    # Get local groups, sessions, etc by feeding data to GenericParser class
    #
    @staticmethod
    def parse_local_objects(file):
        return GenericParser.parse_file(file, is_outflankc2=True)