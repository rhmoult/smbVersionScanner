#!/usr/bin/env python

# This script will take an IP and port (usually 445) to test which version of SMB is reported by the remote host

from impacket.smbconnection import *
from impacket.nmb import NetBIOSError
import errno

def main(rhost, rport):
    host = rhost
    port = int(rport)

    try:
        smb = SMBConnection(host, host, sess_port=port)

    except NetBIOSError:
        print "SMB does not appear to be supported on this host/port."
        return

    except socket.error, v:
        error_code = v[0]
        if error_code == errno.ECONNREFUSED:
            print "Connection refused."
            return
        else:
            print "Something went wrong; that's all I know."
            return

    dialect = smb.getDialect()

    if dialect == SMB_DIALECT:
        print("SMBv1 dialect used")
    elif dialect == SMB2_DIALECT_002:
        print("SMBv2.0 dialect used")
    elif dialect == SMB2_DIALECT_21:
        print("SMBv2.1 dialect used")
    else:
        print("SMBv3.0 dialect used")

if __name__ == "__main__":
    remote_ip = raw_input("What is the remote IP ? ")
    remote_port = raw_input("What is the remote port? (Usually 445) ")
    main(remote_ip, remote_port)