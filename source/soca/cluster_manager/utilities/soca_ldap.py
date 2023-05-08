######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

"""
Import or Export SOCA OpenLDAP
--------
> Export current environment
    /apps/soca/<YOUR_CLUSTER_ID>/python/latest/bin/python3 soca_ldap_utility.py --action export

> Import LDIF
    /apps/soca/<YOUR_CLUSTER_ID>/python/latest/bin/python3 soca_ldap_utility.py --action import --ldif /path/to/file.ldif

# If you want to generate the LDIF via native Linux (example):
ldapsearch -x -D "cn=admin,dc=soca,dc=local" -W -y /root/OpenLdapAdminPassword.txt -b "dc=soca,dc=local" >> soca_export.ldif
ldapadd -x -W -y /root/OpenLdapAdminPassword.txt -D "cn=admin,dc=soca,dc=local" -f soca_export.ldif
"""

import argparse
import os
import sys
import uuid

try:
    import ldap
    from ldif import LDIFWriter, LDIFParser
except ImportError:
    print(
        f"Unable to import ldap/ldif. Make sure to use SOCA python (/apps/soca/<YOUR_CLUSTER_ID>/python/latest/bin/python3 and not system python"
    )
    exit(1)
sys.path.append(os.path.dirname(__file__))


def ldap_export():
    print(f"Exporting LDAP environment")
    try:
        all_entries = conn.search_s(search_base, search_scope)
        ldif_file = f"soca_export_{uuid.uuid4()}.ldif"
        ldif_content = []
        for entry in all_entries:
            print(f"Export {entry[0]}")
            ldif_content.append(entry)

        print(f"Creating LDIF: {ldif_file}")
        ldif_writer = LDIFWriter(open(ldif_file, "wb"))
        for content in ldif_content:
            dn = content[0]
            record = content[1]
            ldif_writer.unparse(dn, record)
    except Exception as err:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(
            f"Unable to export LDAP environment due to {err}. {exc_type}, {fname}, {exc_tb.tb_lineno}"
        )
        sys.exit(1)


def ldap_import(ldif_file):
    print(f"Importing LDAP environment from {ldif_file}")
    try:
        parser = LDIFParser(open(ldif_file, "rb"))
        for dn, record in parser.parse():
            print(f"Importing {dn}")
            # print(record) # Uncomment this file to print record if you want to debug
            tuple_list_as_bytes = []
            for attribute_name, attribute_values in record.items():
                value_as_bytes = []
                for value in attribute_values:
                    value_as_bytes.append(value.encode("utf-8"))  # str to bytes
                tuple_list_as_bytes.append((attribute_name, value_as_bytes))

            try:
                conn.add_s(dn, tuple_list_as_bytes)
                print("Import successful")
            except ldap.ALREADY_EXISTS:
                print("Entry already existing in your LDAP, ignoring ...")
            except Exception as err:
                print(f"Unable to import record due to {err}")

    except FileNotFoundError:
        print(f"Unable to locate {ldif_file}. Make sure the path is correct")
        sys.exit(1)
    except ValueError as err:
        print(
            f"Unable to read ldif. Make sure the LDIF was created with this utility. Error {err}"
        )
        sys.exit(1)

    except Exception as err:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(
            f"Unable to import LDAP environment due to {err}. {exc_type}, {fname}, {exc_tb.tb_lineno}"
        )
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--action",
        nargs="?",
        required=True,
        choices=["import", "export"],
        help="Choose whether you want to export or import LDIF",
    )
    parser.add_argument("--base-dn", nargs="?", help="The LDAP Base")
    parser.add_argument("--ldif", nargs="?", help="Path to LDIF file to import")

    args = parser.parse_args()
    ldap_host = "127.0.0.1"
    if not args.base_dn:
        base_dn = "DC=soca,DC=local"
        print(f" --base-dn not specified, default to {base_dn}")
    else:
        base_dn = args["base_dn"]
        print(f"BaseDN configured to {base_dn}")

    admin_user_bind = f"CN=admin,{base_dn}"
    print(f"Admin User bind configured to {admin_user_bind}")
    admin_user_password_file = "/root/OpenLdapAdminPassword.txt"

    try:
        with open(admin_user_password_file) as f:
            print(f"Retrieving password from {admin_user_password_file}")
            admin_user_password = f.read().rstrip().lstrip().replace("\n", "")
    except FileNotFoundError:
        print(f"{admin_user_password_file} does not exist")
        sys.exit(1)
    except Exception as err:
        print(f"Unable to retrieve Admin password due to {err}")

    search_base = base_dn
    search_scope = ldap.SCOPE_SUBTREE
    try:
        conn = ldap.initialize(f"ldap://{ldap_host}")
        conn.simple_bind_s(admin_user_bind, admin_user_password)
    except ldap.INVALID_CREDENTIALS:
        print("Username or Password incorrect")
        sys.exit(1)
    except Exception as err:
        print(f"Unable to connect to ldap://{ldap_host} due to {err}")
        sys.exit(1)

    if args.action == "export":
        ldap_export()
    else:
        if not args.ldif:
            print("--ldif is required during import. Specify a LDIF file to import")
            sys.exit(1)
        ldap_import(args.ldif)
