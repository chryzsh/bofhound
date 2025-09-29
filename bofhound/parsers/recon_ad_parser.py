import re
import codecs
import datetime

from bofhound.logger import logger
from bofhound.parsers.ldap_search_bof import LdapSearchBofParser


class ReconAdParser(LdapSearchBofParser):
    """
    Parser for ReconAD BOF output.

    ReconAD uses a different output format compared to standard ldapsearch:
    - Uses longer boundary delimiters (--------------------------------------------------------------------)
    - Attributes formatted as "[+] attribute:" instead of "attribute:"
    - Values are indented with 4 spaces
    - Includes additional password expiration information
    """

    RESULT_DELIMITER = "-"
    RESULT_BOUNDARY_LENGTH = 68  # ReconAD uses longer boundary lines
    _COMPLETE_BOUNDARY_LINE = -1

    def __init__(self):
        super().__init__()

    @staticmethod
    def parse_file(file):
        """Parse ReconAD output from file"""
        return ReconAdParser.parse_data(
            ReconAdParser.prep_file(file)
        )

    @staticmethod
    def prep_file(file):
        """Prepare ReconAD file for parsing by cleaning C2 artifacts"""
        with codecs.open(file, 'r', 'utf-8') as f:
            contents = f.read()

        # Remove common C2 timestamp and output artifacts
        # Handle both UTC timestamps and "received output:" lines
        contents = re.sub(r'\n\n\d{2}\/\d{2} (\d{2}:){2}\d{2} UTC \[output\]\nreceived output:\n', '', contents)
        contents = re.sub(r'\n\d{2}\/\d{2} (\d{2}:){2}\d{2} UTC \[output\]\n', '', contents)

        return contents

    @staticmethod
    def parse_data(data):
        """
        Parse ReconAD data format into objects.

        ReconAD format:
        --------------------------------------------------------------------
        [+] attribute:
            value
        [+] another_attribute:
            another_value
        --------------------------------------------------------------------
        """
        parsed_objects = []
        current_object = None
        in_result_region = False
        previous_attr = None

        lines = data.splitlines()
        line_iter = iter(enumerate(lines))

        for line_num, line in line_iter:
            is_boundary_line = ReconAdParser._is_boundary_line(line)

            if (not in_result_region and not is_boundary_line):
                continue

            # Handle multi-line boundary detection for ReconAD's longer delimiters
            if (is_boundary_line and is_boundary_line != ReconAdParser._COMPLETE_BOUNDARY_LINE):
                while True:
                    try:
                        next_line_num, next_line = next(line_iter)
                        remaining_length = ReconAdParser._is_boundary_line(next_line, is_boundary_line)

                        if remaining_length:
                            is_boundary_line = remaining_length
                            if is_boundary_line == ReconAdParser._COMPLETE_BOUNDARY_LINE:
                                break
                    except StopIteration:
                        break

            if is_boundary_line:
                if not in_result_region:
                    in_result_region = True
                elif current_object is not None and current_object:  # Only add if object has content
                    parsed_objects.append(current_object)
                current_object = {}
                previous_attr = None
                continue

            # Check for end of results
            elif re.match(r"^(R|r)etr(e|i)(e|i)ved \d+ results?", line):
                if current_object is not None:
                    parsed_objects.append(current_object)
                in_result_region = False
                current_object = None
                previous_attr = None
                continue

            # Parse ReconAD attribute format: "[+] attribute:"
            if line.strip().startswith('[+] ') and line.strip().endswith(':'):
                attr = line.strip()[4:-1].lower()  # Remove "[+] " and ":"
                previous_attr = attr
                current_object[attr] = ""
                continue

            # Parse indented values (ReconAD indents values with 4 spaces)
            elif line.startswith('    ') and previous_attr is not None:
                value = line.strip()
                if current_object[previous_attr]:
                    # Multi-value attribute, append with comma separator
                    current_object[previous_attr] += ", " + value
                else:
                    # First value for this attribute
                    current_object[previous_attr] = value
                continue

            # Handle password expiration information (ReconAD specific)
            elif line.strip().startswith('[+] Password expire settings:'):
                previous_attr = 'password_expire_settings'
                current_object[previous_attr] = ""
                continue

            # Handle account status lines
            elif previous_attr == 'password_expire_settings' and line.strip() and not line.strip().startswith('[+]'):
                value = line.strip()
                if current_object[previous_attr]:
                    current_object[previous_attr] += "; " + value
                else:
                    current_object[previous_attr] = value
                continue

            # Handle any remaining content that might be continuation of previous attribute
            elif line.strip() and previous_attr is not None:
                value = line.strip()
                if not value.startswith('['):  # Skip other ReconAD specific markers
                    if current_object[previous_attr]:
                        current_object[previous_attr] += " " + value
                    else:
                        current_object[previous_attr] = value

        # Add the last object if we have one
        if current_object is not None and current_object:  # Only add if object has content
            parsed_objects.append(current_object)

        # Post-process to convert ReconAD timestamp formats to FILETIME
        ReconAdParser._convert_timestamps(parsed_objects)

        return parsed_objects

    @staticmethod
    def _convert_timestamps(objects):
        """
        Convert ReconAD human-readable timestamps to Windows FILETIME format.

        ReconAD outputs timestamps like '9/15/2025 7:38:36 AM'
        BOFHound expects Windows FILETIME integers.
        """
        # Timestamp fields that need conversion
        timestamp_fields = [
            'lastlogontimestamp', 'lastlogon', 'pwdlastset',
            'badpasswordtime', 'accountexpires', 'whencreated', 'whenchanged'
        ]

        for obj in objects:
            for field in timestamp_fields:
                if field in obj and obj[field]:
                    try:
                        # Try to convert ReconAD timestamp format
                        converted = ReconAdParser._parse_reconad_timestamp(obj[field])
                        if converted is not None:
                            obj[field] = str(converted)
                        else:
                            # Remove field if it cannot be converted
                            del obj[field]
                    except Exception as e:
                        logger.debug(f'Failed to convert timestamp {field}: {obj[field]} - {e}')
                        # Remove field if conversion fails
                        del obj[field]

    @staticmethod
    def _parse_reconad_timestamp(timestamp_str):
        """
        Parse ReconAD timestamp format and convert to Windows FILETIME.

        Args:
            timestamp_str: String like '9/15/2025 7:38:36 AM' or 'Never Expires.' or 'No value set.'

        Returns:
            int: Windows FILETIME value or None if cannot parse
        """
        if not timestamp_str or timestamp_str.strip() in ['No value set.', 'Never Expires.']:
            return None

        try:
            # Try common ReconAD date formats
            formats = [
                '%m/%d/%Y %I:%M:%S %p',  # 9/15/2025 7:38:36 AM
                '%m/%d/%Y %H:%M:%S',     # 9/15/2025 19:38:36
                '%Y-%m-%d %H:%M:%S',     # 2025-09-15 19:38:36
            ]

            dt = None
            for fmt in formats:
                try:
                    dt = datetime.datetime.strptime(timestamp_str.strip(), fmt)
                    break
                except ValueError:
                    continue

            if dt is None:
                return None

            # Convert to Windows FILETIME (100-nanosecond intervals since January 1, 1601 UTC)
            epoch = datetime.datetime(1601, 1, 1)
            delta = dt - epoch
            filetime = int(delta.total_seconds() * 10000000)
            return filetime

        except Exception as e:
            logger.debug(f'Failed to parse timestamp: {timestamp_str} - {e}')
            return None

    @staticmethod
    def _is_boundary_line(line, length=RESULT_BOUNDARY_LENGTH):
        """
        Check if line is a ReconAD boundary line.

        Returns:
            0 - Not a boundary line
            -1 - Complete boundary line
            n - Remaining characters needed for complete boundary
        """
        line = line.strip()
        chars = set(line)

        if len(chars) == 1 and chars.pop() == ReconAdParser.RESULT_DELIMITER:
            if len(line) == length:
                return -1
            elif len(line) < length:
                return ReconAdParser.RESULT_BOUNDARY_LENGTH - len(line)

        return 0

    @staticmethod
    def normalize_to_ldapsearch_format(recon_objects):
        """
        Convert ReconAD parsed objects to ldapsearch-compatible format.

        This allows ReconAD objects to be processed by existing BOFHound
        ldapsearch processing logic.
        """
        normalized_objects = []

        for obj in recon_objects:
            normalized_obj = {}

            for attr, value in obj.items():
                # Convert ReconAD specific attributes to ldapsearch equivalents
                if attr == 'password_expire_settings':
                    # This is ReconAD specific, keep as-is for now
                    normalized_obj[attr] = value
                else:
                    # Standard LDAP attributes should work as-is
                    normalized_obj[attr] = value

            normalized_objects.append(normalized_obj)

        return normalized_objects

    @staticmethod
    def parse_local_objects(data):
        """Parse local objects using GenericParser for compatibility"""
        from bofhound.parsers.generic_parser import GenericParser
        return GenericParser.parse_data(data)