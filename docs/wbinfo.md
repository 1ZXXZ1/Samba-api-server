WBINFO(1)                                                         User Commands                                                        WBINFO(1)

NAME
       wbinfo - Query information from winbind daemon

SYNOPSIS
       wbinfo [-a user%password] [--all-domains] [--allocate-gid] [--allocate-uid] [-c] [--ccache-save] [--change-user-password] [-D domain]
        [--dc-info domain] [--domain domain] [--dsgetdcname domain] [-g] [--getdcname domain] [--get-auth-user] [-G gid] [--gid-info gid]
        [--group-info group] [--help|-?] [-i user] [-I ip] [-K user%password] [--krb5ccname cctype] [--lanman] [--logoff] [--logoff-uid uid]
        [--logoff-user username] [--lookup-sids] [-m] [-n name] [-N netbios-name] [--ntlmv1] [--ntlmv2] [--online-status] [--own-domain] [-p]
        [-P|--ping-dc] [--pam-logon user%password] [-r user] [-R|--lookup-rids] [--remove-gid-mapping gid,sid] [--remove-uid-mapping uid,sid]
        [-s sid] [--separator] [--sequence] [--set-auth-user user%password] [--set-gid-mapping gid,sid] [--set-uid-mapping uid,sid] [-S sid]
        [--sid-aliases sid] [--sid-to-fullname sid] [--sids-to-unix-ids sidlist] [-t] [-u] [--uid-info uid] [--usage] [--user-domgroups sid]
        [--user-sidinfo sid] [--user-sids sid] [-U uid] [-V] [--verbose] [-Y sid]

DESCRIPTION
       This tool is part of the samba(7) suite.

       The wbinfo program queries and returns information created and used by the winbindd(8) daemon.

       The winbindd(8) daemon must be configured and running for the wbinfo program to be able to return information.

OPTIONS
       -a|--authenticate username%password
           Attempt to authenticate a user via winbindd(8). This checks both authentication methods and reports its results.

               Note
               Do not be tempted to use this functionality for authentication in third-party applications. Instead use ntlm_auth(1).

       --allocate-gid
           Get a new GID out of idmap

       --allocate-uid
           Get a new UID out of idmap

       --all-domains
           List all domains (trusted and own domain).

       -c|--change-secret
           Change the trust account password. May be used in conjunction with domain in order to change interdomain trust account passwords.

       --change-secret-at domain-controller
           Change the trust account password at a specific domain controller. Fails if the specified domain controller cannot be contacted.

       --ccache-save username%password
           Store user and password for ccache.

       --change-user-password username
           Change the password of a user. The old and new password will be prompted.

       --dc-info domain
           Displays information about the current domain controller for a domain.

       --domain name
           This parameter sets the domain on which any specified operations will performed. If special domain name '.' is used to represent the
           current domain to which winbindd(8) belongs. A '*' as the domain name means to enumerate over all domains (NOTE: This can take a long
           time and use a lot of memory).

       -D|--domain-info domain
           Show most of the info we have about the specified domain.

       --dsgetdcname domain
           Find a DC for a domain.

       --gid-info gid
           Get group info from gid.

       --group-info group
           Get group info from group name.

       -g|--domain-groups
           This option will list all groups available in the Windows NT domain for which the samba(7) daemon is operating in. Groups in all
           trusted domains can be listed with the --domain='*' option. Note that this operation does not assign group ids to any groups that
           have not already been seen by winbindd(8).

       --get-auth-user
           Print username and password used by winbindd(8) during session setup to a domain controller. Username and password can be set using
           --set-auth-user. Only available for root.

       --getdcname domain
           Get the DC name for the specified domain.

       -G|--gid-to-sid gid
           Try to convert a UNIX group id to a Windows NT SID. If the gid specified does not refer to one within the idmap gid range then the
           operation will fail.

       -?
           Print brief help overview.

       -i|--user-info user
           Get user info.

       -I|--WINS-by-ip ip
           The -I option queries winbindd(8) to send a node status request to get the NetBIOS name associated with the IP address specified by
           the ip parameter.

       -K|--krb5auth username%password
           Attempt to authenticate a user via Kerberos.

       --krb5ccname KRB5CCNAME
           Allows one to request a specific kerberos credential cache type used for authentication.

       --lanman
           Use lanman cryptography for user authentication.

       --logoff
           Logoff a user.

       --logoff-uid UID
           Define user uid used during logoff request.

       --logoff-user USERNAME
           Define username used during logoff request.

       --lookup-sids SID1,SID2...
           Looks up SIDs. SIDs must be specified as ASCII strings in the traditional Microsoft format. For example,
           S-1-5-21-1455342024-3071081365-2475485837-500.

       -m|--trusted-domains
           Produce a list of domains trusted by the Windows NT server winbindd(8) contacts when resolving names. This list does not include the
           Windows NT domain the server is a Primary Domain Controller for.

       -n|--name-to-sid name
           The -n option queries winbindd(8) for the SID associated with the name specified. Domain names can be specified before the user name
           by using the winbind separator character. For example CWDOM1/Administrator refers to the Administrator user in the domain CWDOM1. If
           no domain is specified then the domain used is the one specified in the smb.conf(5) workgroup parameter.

       -N|--WINS-by-name name
           The -N option queries winbindd(8) to query the WINS server for the IP address associated with the NetBIOS name specified by the name
           parameter.

       --ntlmv1
           Use NTLMv1 cryptography for user authentication.

       --ntlmv2
           Use NTLMv2 cryptography for user authentication. NTLMv2 is the default method, this option is only maintained for compatibility.

       --online-status domain
           Display whether winbind currently maintains an active connection or not. An optional domain argument limits the output to the online
           status of a given domain.

       --own-domain
           List own domain.

       --pam-logon username%password
           Attempt to authenticate a user in the same way pam_winbind would do.

       -p|--ping
           Check whether winbindd(8) is still alive. Prints out either 'succeeded' or 'failed'.

       -P|--ping-dc
           Issue a no-effect command to our DC. This checks if our secure channel connection to our domain controller is still alive. It has
           much less impact than wbinfo -t.

       -r|--user-groups username
           Try to obtain the list of UNIX group ids to which the user belongs. This only works for users defined on a Domain Controller.

           There are two scenaries:

                   1. User authenticated: When the user has been authenticated, the access token for the user is cached. The correct group
                      memberships are then returned from the cached user token (which can be outdated).

                   2. User *NOT* authenticated: The information is queries from the domain controller using the machine account credentials
                      which have limited permissions. The result is normally incomplete and can be also incorrect.

       -R|--lookup-rids rid1, rid2, rid3...
           Converts RIDs to names. Uses a comma separated list of rids.

       --remove-gid-mapping GID,SID
           Removes an existing GID to SID mapping from the database.

       --remove-uid-mapping UID,SID
           Removes an existing UID to SID mapping from the database.

       -s|--sid-to-name sid
           Use -s to resolve a SID to a name. This is the inverse of the -n option above. SIDs must be specified as ASCII strings in the
           traditional Microsoft format. For example, S-1-5-21-1455342024-3071081365-2475485837-500.

       --separator
           Get the active winbind separator.

       --sequence
           This command has been deprecated. Please use the --online-status option instead.

       --set-auth-user username%password
           Store username and password used by winbindd(8) during session setup to a domain controller. This enables winbindd to operate in a
           Windows 2000 domain with Restrict Anonymous turned on (a.k.a. Permissions compatible with Windows 2000 servers only).

       --set-gid-mapping GID,SID
           Create a GID to SID mapping in the database.

       --set-uid-mapping UID,SID
           Create a UID to SID mapping in the database.

       -S|--sid-to-uid sid
           Convert a SID to a UNIX user id. If the SID does not correspond to a UNIX user mapped by winbindd(8) then the operation will fail.

       --sid-aliases sid
           Get SID aliases for a given SID.

       --sid-to-fullname sid
           Converts a SID to a full username (DOMAIN\username).

       --sids-to-unix-ids sid1,sid2,sid3...
           Resolve SIDs to Unix IDs. SIDs must be specified as ASCII strings in the traditional Microsoft format. For example,
           S-1-5-21-1455342024-3071081365-2475485837-500.

       -t|--check-secret
           Verify that the workstation trust account created when the Samba server is added to the Windows NT domain is working. May be used in
           conjunction with domain in order to verify interdomain trust accounts.

       -u|--domain-users
           This option will list all users available in the Windows NT domain for which the winbindd(8) daemon is operating in. Users in all
           trusted domains can be listed with the --domain='*' option. Note that this operation does not assign user ids to any users that have
           not already been seen by winbindd(8) .

       --uid-info uid
           Get user info for the user connected to user id UID.

       --usage
           Print brief help overview.

       --user-domgroups sid
           Get user domain groups.

       --user-sidinfo sid
           Get user info by sid.

       --user-sids sid
           Get user group SIDs for user.

       -U|--uid-to-sid uid
           Try to convert a UNIX user id to a Windows NT SID. If the uid specified does not refer to one within the idmap range then the
           operation will fail.

       --verbose
           Print additional information about the query results.

       -Y|--sid-to-gid sid
           Convert a SID to a UNIX group id. If the SID does not correspond to a UNIX group mapped by winbindd(8) then the operation will fail.

       -V|--version
           Prints the program version number.

       -?|--help
           Print a summary of command line options.

       --usage
           Display brief usage message.

EXIT STATUS
       The wbinfo program returns 0 if the operation succeeded, or 1 if the operation failed. If the winbindd(8) daemon is not working wbinfo
       will always return failure.

VERSION
       This man page is part of version 4.21.9-alt1 of the Samba suite.

SEE ALSO
       winbindd(8) and ntlm_auth(1)

AUTHOR
       The original Samba software and related utilities were created by Andrew Tridgell. Samba is now developed by the Samba Team as an Open
       Source project similar to the way the Linux kernel is developed.

       wbinfo and winbindd were written by Tim Potter.

       The conversion to DocBook for Samba 2.2 was done by Gerald Carter. The conversion to DocBook XML 4.2 for Samba 3.0 was done by Alexander
       Bokovoy.

Samba 4.21.9-alt1                                                  10/24/2025                                                          WBINFO(1)
