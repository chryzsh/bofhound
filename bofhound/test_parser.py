import json
from pprint import pprint

# Adjust this import path if your file is in a different location
# e.g., from bofhound.parsers.outflankc2 import OutflankC2JsonParser
from parsers.outflankc2 import OutflankC2JsonParser 

# --- CONFIGURATION ---
# IMPORTANT: Update this path to point to your actual JSON log file
LOG_FILE_PATH = '../../B6XAITD6.json' 
# --- END CONFIGURATION ---

def main():
    """
    Runs the parser and prints the first computer object for inspection.
    """
    print(f"[*] Reading and preparing log file: {LOG_FILE_PATH}")
    try:
        file_content = OutflankC2JsonParser.prep_file(LOG_FILE_PATH)
        print("[*] Running the parse_data method...")
        parsed_objects = OutflankC2JsonParser.parse_data(file_content)
        
        print(f"\n[+] Success! Parser produced {len(parsed_objects)} objects.")
        
        if parsed_objects:
            print("\n--- Inspecting the first parsed COMPUTER object ---")
            # Find the first object that should be a computer
            first_computer = None
            for obj in parsed_objects:
                # bofhound looks for 'computer' in the objectclass list
                if 'objectclass' in obj and 'computer' in obj.get('objectclass', []):
                    first_computer = obj
                    break
            
            if first_computer:
                pprint(first_computer)
            else:
                print("\n[!] CRITICAL: Could not find any computer objects.")
                print("[!] This likely means 'objectclass' is not being parsed correctly.")
                print("\n--- Printing the very first object found for clues ---")
                pprint(parsed_objects[0])

    except FileNotFoundError:
        print(f"\n[!] ERROR: The file was not found at '{LOG_FILE_PATH}'")
    except Exception as e:
        print(f"\n[!] An error occurred during parsing: {e}")

if __name__ == "__main__":
    main()
