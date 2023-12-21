#!/usr/bin/env python

# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.


import base64
from binascii import hexlify
import getpass
import os
import select
import socket
import sys
import time
import traceback
# ??question: why the input module imported as third party import and not in the usual way when standard library import is used?
# question??
""" 
!!answer Python allows different ways of import modules. The standard way is possible here, but using third party import 
helps to reduce the code length and repeatability as it is used rather often. answer!!
"""

from paramiko.py3compat import input

import paramiko

try:
    import interactive
except ImportError:
    from . import interactive


# ??question: what is the type of transport parameter?
# question??
"""
!!answer It has the type of ServiceRequestingTransport or Transport object defined in paramiko in file transport.py. answer!!  
"""
def agent_auth(transport, username):
    """
    Attempt to authenticate to the given transport using any of the private
    keys available from an SSH agent.
    """

    agent = paramiko.Agent()
    # ??question: what is the default value of agent_keys?
    # question??
    """
    !!answer As it is defined in AgentSSH class which is inherited by Agent class is paramiko, get_keys() returnes the
    a tuple of AgentKey objects representing keys available on the SSH agent. The default value of it is () which 
    is actually an empty tuple. answer!!
    """
    agent_keys = agent.get_keys()
    if len(agent_keys) == 0:
        return

    # ??question: what is the type of key variable?
    # question??
    """
    !!answer As agent_keys represents the tuple of AgentKey objects, the type of values in it will be AgentKey objects. answer!!
    """
    for key in agent_keys:
        print("Trying ssh-agent key %s" % hexlify(key.get_fingerprint()))
        try:
            # ??question: what is the successful result of auth_publickey function?
            # question??
            """
            !!answer When finishing successfully, the auth_publickey function provides authentification to the server
            using the private key and returns the list of auth types permissible for the next stage of authentication which is normally empty. answer!!
            """
            transport.auth_publickey(username, key)
            print("... success!")
            return
        except paramiko.SSHException:
            print("... nope.")


def manual_auth(username, hostname):
    default_auth = "p"
    # ??question: what is the default value of auth?
    # question??
    """
    !!answer The default value of auth after an empty input (which is the default input) is an empty string
    but just after the input there is a condition whuch turnes auth itto the default_auth which is actually "p". answer!!
    """
    # ??question: on what condition the length of auth is equal to 0?
    # question??
    """
    !!answer If the user submits an empty input ut makes an auth variable to be an empty string which length is equal to 0. answer!!
    """
    auth = input(
        "Auth by (p)assword, (r)sa key, or (d)ss key? [%s] " % default_auth
    )
    if len(auth) == 0:
        auth = default_auth

    if auth == "r":
        default_path = os.path.join(os.environ["HOME"], ".ssh", "id_rsa")
        path = input("RSA key [%s]: " % default_path)
        if len(path) == 0:
            path = default_path
        try:
            key = paramiko.RSAKey.from_private_key_file(path)
        except paramiko.PasswordRequiredException:
            password = getpass.getpass("RSA key password: ")
            # ??question: what is the value of key if the incorrect password is submitted?
            # question??
            key = paramiko.RSAKey.from_private_key_file(path, password)
        # ??question: where is the declaration of t?
        # question??
        t.auth_publickey(username, key)
    elif auth == "d":
        default_path = os.path.join(os.environ["HOME"], ".ssh", "id_dsa")
        path = input("DSS key [%s]: " % default_path)
        if len(path) == 0:
            path = default_path
        try:
            key = paramiko.DSSKey.from_private_key_file(path)
        except paramiko.PasswordRequiredException:
            password = getpass.getpass("DSS key password: ")
            key = paramiko.DSSKey.from_private_key_file(path, password)
        t.auth_publickey(username, key)
    else:
        pw = getpass.getpass("Password for %s@%s: " % (username, hostname))
        t.auth_password(username, pw)


# setup logging
# ??question: does the log_to_file function creates the empty logfile or writes in the existing one?
# question??
"""
!!answer: The file upened with log_to_file is opened using open(filename, "a") python standard command
according to its definition in paramiko/util.py. The file opened this way is being created if it doesn't
exist or the contents are being written at the file's end if the file already exists. answer!!
"""
# ??question: is it possible to select a custom logfile name by user input in log_to_file?
# question??
"""
!!answer It is possible to do it using the log_to_file function. All you need is to specify the desired filename
as an argument for the function. For example, your code can look like that: `paramiko.util.log_to_file("my.filename")`. answer!!
"""
paramiko.util.log_to_file("demo.log")

username = ""
if len(sys.argv) > 1:
    hostname = sys.argv[1]
    if hostname.find("@") >= 0:
        username, hostname = hostname.split("@")
else:
    hostname = input("Hostname: ")
if len(hostname) == 0:
    print("*** Hostname required.")
    sys.exit(1)
# ??question: is it possible to select the custom port value by user input in port variable?
# question??
"""
!!answer It is possible to do it using port variable. All you need to do is to specify the desired port as an integer value 
for the function. For example, your code can look like that: `port = 42`. answer!!
"""
port = 22
if hostname.find(":") >= 0:
    hostname, portstr = hostname.split(":")
    port = int(portstr)

# now connect
try:
    # ??question: what is the default value of sock?
    # question??
    """
    !!answer According to Python documentation socket.socket creates a new object of socket.socket class 
    with family set to AddressFamily.AF_INET and type set to SocketKind.SOCK_STREAM which becomes the default value of sock. answer!!
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((hostname, port))
except Exception as e:
    print("*** Connect failed: " + str(e))
    traceback.print_exc()
    sys.exit(1)

try:
    t = paramiko.Transport(sock)
    try:
        # ??question: what is the successful result of start_client function?
        # question??
        """
        !!answer According to the definition of start_client in paramiko/transport.py this function negotiates a new SSH2 session
        as client. It can raise an exception but has no return value. answer!!
        """
        t.start_client()
    except paramiko.SSHException:
        print("*** SSH negotiation failed.")
        sys.exit(1)

    try:
        keys = paramiko.util.load_host_keys(
            os.path.expanduser("~/.ssh/known_hosts")
        )
    except IOError:
        try:
            keys = paramiko.util.load_host_keys(
                os.path.expanduser("~/ssh/known_hosts")
            )
        except IOError:
            print("*** Unable to open host keys file")
            keys = {}

    # check server's host key -- this is important.
    key = t.get_remote_server_key()
    if hostname not in keys:
        print("*** WARNING: Unknown host key!")
    elif key.get_name() not in keys[hostname]:
        print("*** WARNING: Unknown host key!")
    elif keys[hostname][key.get_name()] != key:
        print("*** WARNING: Host key has changed!!!")
        sys.exit(1)
    else:
        print("*** Host key OK.")

    # get username
    if username == "":
        # ??question: what is the default value of default_username?
        # question??
        """
        !!answer According to the documentation of getpass module, this value returnes the "login name" of the user. 
        This function checks the environment variables LOGNAME, USER, LNAME and USERNAME, in order, and returns the 
        value of the first one which is set to a non-empty string. If none are set, the login name from the password 
        database is returned on systems which support the pwd module, otherwise, an exception is raised.
        This means that the default value of default_user will be its login name if exists. answer!!
        """
        default_username = getpass.getuser()
        username = input("Username [%s]: " % default_username)
        if len(username) == 0:
            username = default_username

    agent_auth(t, username)
    if not t.is_authenticated():
        manual_auth(username, hostname)
    if not t.is_authenticated():
        print("*** Authentication failed. :(")
        t.close()
        sys.exit(1)

    # ??question: what is the type of chan?
    # question??
    """
    !!answer The type of chan is the object of Channel class defined in paramiko/channel.py as the return type of open_session function
    has this type. answer!!
    """
    chan = t.open_session()
    chan.get_pty()
    chan.invoke_shell()
    print("*** Here we go!\n")
    interactive.interactive_shell(chan)
    chan.close()
    t.close()

except Exception as e:
    print("*** Caught exception: " + str(e.__class__) + ": " + str(e))
    traceback.print_exc()
    try:
        t.close()
    except:
        pass
    sys.exit(1)
