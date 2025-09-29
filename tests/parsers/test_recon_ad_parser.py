import unittest
from bofhound.parsers.recon_ad_parser import ReconAdParser


class TestReconAdParser(unittest.TestCase):

    def test_boundary_line_detection(self):
        """Test ReconAD boundary line detection"""
        # Complete boundary line (68 dashes)
        complete_boundary = "-" * 68
        self.assertEqual(ReconAdParser._is_boundary_line(complete_boundary), -1)

        # Incomplete boundary line
        incomplete_boundary = "-" * 50
        self.assertEqual(ReconAdParser._is_boundary_line(incomplete_boundary), 18)

        # Not a boundary line
        regular_line = "[+] cn:"
        self.assertEqual(ReconAdParser._is_boundary_line(regular_line), 0)

        # Mixed characters (not a boundary)
        mixed_line = "----abc----"
        self.assertEqual(ReconAdParser._is_boundary_line(mixed_line), 0)

    def test_parse_simple_recon_ad_object(self):
        """Test parsing a simple ReconAD object"""
        sample_data = """--------------------------------------------------------------------
[+] cn:
    testuser
[+] distinguishedName:
    CN=testuser,CN=Users,DC=test,DC=local
[+] objectGUID:
    12345678-1234-1234-1234-123456789abc
--------------------------------------------------------------------"""

        result = ReconAdParser.parse_data(sample_data)

        self.assertEqual(len(result), 1)
        obj = result[0]

        self.assertEqual(obj['cn'], 'testuser')
        self.assertEqual(obj['distinguishedname'], 'CN=testuser,CN=Users,DC=test,DC=local')
        self.assertEqual(obj['objectguid'], '12345678-1234-1234-1234-123456789abc')

    def test_parse_multi_value_attributes(self):
        """Test parsing attributes with multiple values"""
        sample_data = """--------------------------------------------------------------------
[+] objectClass:
    top
    person
    organizationalPerson
    user
[+] servicePrincipalName:
    MSSQLSvc/server1.domain.local:1433
    MSSQLSvc/server1.domain.local
--------------------------------------------------------------------"""

        result = ReconAdParser.parse_data(sample_data)

        self.assertEqual(len(result), 1)
        obj = result[0]

        self.assertEqual(obj['objectclass'], 'top, person, organizationalPerson, user')
        self.assertEqual(obj['serviceprincipalname'], 'MSSQLSvc/server1.domain.local:1433, MSSQLSvc/server1.domain.local')

    def test_parse_password_expiration_data(self):
        """Test parsing ReconAD specific password expiration information"""
        sample_data = """--------------------------------------------------------------------
[+] ADsPath:
    LDAP://CN=testuser,CN=Users,DC=test,DC=local
[+] Password expire settings:
    account enabled
    password expires at: 01-12-2024 15:30:45
--------------------------------------------------------------------"""

        result = ReconAdParser.parse_data(sample_data)

        self.assertEqual(len(result), 1)
        obj = result[0]

        self.assertEqual(obj['adspath'], 'LDAP://CN=testuser,CN=Users,DC=test,DC=local')
        self.assertEqual(obj['password_expire_settings'], 'account enabled; password expires at: 01-12-2024 15:30:45')

    def test_parse_multiple_objects(self):
        """Test parsing multiple ReconAD objects"""
        sample_data = """--------------------------------------------------------------------
[+] cn:
    user1
[+] objectSid:
    S-1-5-21-123456789-123456789-123456789-1001
--------------------------------------------------------------------
[+] cn:
    user2
[+] objectSid:
    S-1-5-21-123456789-123456789-123456789-1002
--------------------------------------------------------------------"""

        result = ReconAdParser.parse_data(sample_data)

        self.assertEqual(len(result), 2)

        self.assertEqual(result[0]['cn'], 'user1')
        self.assertEqual(result[0]['objectsid'], 'S-1-5-21-123456789-123456789-123456789-1001')

        self.assertEqual(result[1]['cn'], 'user2')
        self.assertEqual(result[1]['objectsid'], 'S-1-5-21-123456789-123456789-123456789-1002')

    def test_parse_with_c2_artifacts(self):
        """Test parsing ReconAD data with C2 timestamp artifacts"""
        sample_data = """12/05 02:22:43 UTC [output]
received output:

--------------------------------------------------------------------
[+] cn:
    testuser
[+] sAMAccountName:
    testuser
--------------------------------------------------------------------

retrieved 1 results total"""

        result = ReconAdParser.parse_data(ReconAdParser.prep_file_data(sample_data))

        self.assertEqual(len(result), 1)
        obj = result[0]

        self.assertEqual(obj['cn'], 'testuser')
        self.assertEqual(obj['samaccountname'], 'testuser')

    def test_normalize_to_ldapsearch_format(self):
        """Test normalization of ReconAD objects to ldapsearch format"""
        recon_objects = [
            {
                'cn': 'testuser',
                'objectsid': 'S-1-5-21-123456789-123456789-123456789-1001',
                'password_expire_settings': 'account enabled; password never expires'
            }
        ]

        normalized = ReconAdParser.normalize_to_ldapsearch_format(recon_objects)

        self.assertEqual(len(normalized), 1)
        obj = normalized[0]

        # Standard attributes should be preserved
        self.assertEqual(obj['cn'], 'testuser')
        self.assertEqual(obj['objectsid'], 'S-1-5-21-123456789-123456789-123456789-1001')

        # ReconAD specific attributes should be preserved
        self.assertEqual(obj['password_expire_settings'], 'account enabled; password never expires')

    def test_empty_input(self):
        """Test parsing empty input"""
        result = ReconAdParser.parse_data("")
        self.assertEqual(len(result), 0)

    def test_no_objects_found(self):
        """Test parsing input with no valid objects"""
        sample_data = """Some random log output
No ReconAD boundaries found here
Just regular text"""

        result = ReconAdParser.parse_data(sample_data)
        self.assertEqual(len(result), 0)

    @staticmethod
    def prep_file_data(data):
        """Helper method to simulate prep_file functionality for testing"""
        import re
        data = re.sub(r'\n\n\d{2}\/\d{2} (\d{2}:){2}\d{2} UTC \[output\]\nreceived output:\n', '', data)
        data = re.sub(r'\n\d{2}\/\d{2} (\d{2}:){2}\d{2} UTC \[output\]\n', '', data)
        return data


if __name__ == '__main__':
    unittest.main()