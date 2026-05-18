SAMBA-TOOL(8)                                                System Administration tools                                                SAMBA-TOOL(8)

NAME
       samba-tool - Main Samba administration tool.

SYNOPSIS
       samba-tool [-h] [-W myworkgroup] [-U user] [-d debuglevel] [--v]

DESCRIPTION
       This tool is part of the samba(7) suite.

OPTIONS
       -h|--help
           Show this help message and exit

       -r|--realm=REALM
           Set the realm for the domain.

           Note that specifying this parameter here will override the realm parameter in the /etc/samba/smb.conf file.

       --simple-bind-dn=DN
           DN to use for a simple bind.

       --password
           Specify the password on the commandline.

           Be cautious about including passwords in scripts or passing user-supplied values onto the command line. For security it is better to let
           the Samba client tool ask for the password if needed, or obtain the password once with kinit.

           If --password is not specified, the tool will check the PASSWD environment variable, followed by PASSWD_FD which is expected to contain an
           open file descriptor (FD) number.

           Finally it will check PASSWD_FILE (containing a file path to be opened). The file should only contain the password. Make certain that the
           permissions on the file restrict access from unwanted users!

           While Samba will attempt to scrub the password from the process title (as seen in ps), this is after startup and so is subject to a race.

       -U|--user=[DOMAIN\]USERNAME[%PASSWORD]
           Sets the SMB username or username and password.

           If %PASSWORD is not specified, the user will be prompted. The client will first check the USER environment variable (which is also
           permitted to also contain the password separated by a %), then the LOGNAME variable (which is not permitted to contain a password) and if
           either exists, the value is used. If these environmental variables are not found, the username found in a Kerberos Credentials cache may
           be used.

           A third option is to use a credentials file which contains the plaintext of the username and password. This option is mainly provided for
           scripts where the admin does not wish to pass the credentials on the command line or via environment variables. If this method is used,
           make certain that the permissions on the file restrict access from unwanted users. See the -A for more details.

           Be cautious about including passwords in scripts or passing user-supplied values onto the command line. For security it is better to let
           the Samba client tool ask for the password if needed, or obtain the password once with kinit.

           While Samba will attempt to scrub the password from the process title (as seen in ps), this is after startup and so is subject to a race.

       -W|--workgroup=WORKGROUP
           Set the SMB domain of the username. This overrides the default domain which is the domain defined in smb.conf. If the domain specified is
           the same as the servers NetBIOS name, it causes the client to log on using the servers local SAM (as opposed to the Domain SAM).

           Note that specifying this parameter here will override the workgroup parameter in the /etc/samba/smb.conf file.

       -N|--no-pass
           If specified, this parameter suppresses the normal password prompt from the client to the user. This is useful when accessing a service
           that does not require a password.

           Unless a password is specified on the command line or this parameter is specified, the client will request a password.

           If a password is specified on the command line and this option is also defined the password on the command line will be silently ignored
           and no password will be used.

       --use-kerberos=desired|required|off
           This parameter determines whether Samba client tools will try to authenticate using Kerberos. For Kerberos authentication you need to use
           dns names instead of IP addresses when connecting to a service.

           Note that specifying this parameter here will override the client use kerberos parameter in the /etc/samba/smb.conf file.

       --use-krb5-ccache=CCACHE
           Specifies the credential cache location for Kerberos authentication.

           This will set --use-kerberos=required too.

       -A|--authentication-file=filename
           This option allows you to specify a file from which to read the username and password used in the connection. The format of the file is:

                                   username = <value>
                                   password = <value>
                                   domain   = <value>

           Make certain that the permissions on the file restrict access from unwanted users!

       --ipaddress=IPADDRESS
           IP address of the server

       --color=always|never|auto
           Indicate whether samba-tool should use ANSI colour codes in its output. If 'auto' (the default), samba-tool will use colour when its
           output is directed toward a terminal, unless the NO_COLOR environment variable is set and non-empty.

           The values 'yes' and 'force' are accepted as synonyms for 'always'; 'no' and 'none' for 'never'; and 'tty' and 'if-tty' for 'auto'.

           Note that asking for colour doesn't mean samba-tool will necessarily be very colourful. Many commands are very monochrome, particularly
           when successful.

       -d|--debuglevel=DEBUGLEVEL
           level is an integer from 0 to 10. The default value if this parameter is not specified is 1 for client applications.

           The higher this value, the more detail will be logged to the log files about the activities of the server. At level 0, only critical
           errors and serious warnings will be logged. Level 1 is a reasonable level for day-to-day running - it generates a small amount of
           information about operations carried out.

           Levels above 1 will generate considerable amounts of log data, and should only be used when investigating a problem. Levels above 3 are
           designed for use only by developers and generate HUGE amounts of log data, most of which is extremely cryptic.

           Note that specifying this parameter here will override the log level parameter in the /etc/samba/smb.conf file.

       --debug-stdout
           This will redirect debug output to STDOUT. By default all clients are logging to STDERR.

COMMANDS
   computer
       Manage computer accounts.

   computer add computername [options]
       Add a new computer to the Active Directory Domain.

       The new computer name specified on the command is the sAMAccountName, with or without the trailing dollar sign.

       --computerou=COMPUTEROU
           DN of alternative location (with or without domainDN counterpart) to default CN=Computers in which new computer object will be created.
           E.g. 'OU=OUname'.

       --description=DESCRIPTION
           The new computer's description.

       --ip-address=IP_ADDRESS_LIST
           IPv4 address for the computer's A record, or IPv6 address for AAAA record, can be provided multiple times.

       --service-principal-name=SERVICE_PRINCIPAL_NAME_LIST
           Computer's Service Principal Name, can be provided multiple times.

       --prepare-oldjoin
           Prepare enabled machine account for oldjoin mechanism.

   computer create computername [options]
       Add a new computer. This is a synonym for the samba-tool computer add command and is available for compatibility reasons only. Please use
       samba-tool computer add instead.

   computer delete computername [options]
       Delete an existing computer account.

       The computer name specified on the command is the sAMAccountName, with or without the trailing dollar sign.

   computer edit computername
       Edit a computer AD object.

       The computer name specified on the command is the sAMAccountName, with or without the trailing dollar sign.

       --editor=EDITOR
           Specifies the editor to use instead of the system default, or 'vi' if no system default is set.

   computer list
       List all computers.

   computer move computername new_parent_dn [options]
       This command moves a computer account into the specified organizational unit or container.

       The computername specified on the command is the sAMAccountName, with or without the trailing dollar sign.

       The name of the organizational unit or container can be specified as a full DN or without the domainDN component.

   computer show computername [options]
       Display a computer AD object.

       The computer name specified on the command is the sAMAccountName, with or without the trailing dollar sign.

       --attributes=USER_ATTRS
           Comma separated list of attributes, which will be printed.

   contact
       Manage contacts.

   contact add [contactname] [options]
       Add a new contact to the Active Directory Domain.

       The name of the new contact can be specified by the first argument 'contactname' or the --given-name, --initial and --surname arguments. If no
       'contactname' is given, contact's name will be made up of the given arguments by combining the given-name, initials and surname. Each argument
       is optional. A dot ('.') will be appended to the initials automatically.

       --ou=OU
           DN of alternative location (with or without domainDN counterpart) in which the new contact will be created. E.g. 'OU=OUname'. Default is
           the domain base.

       --description=DESCRIPTION
           The new contact's description.

       --surname=SURNAME
           Contact's surname.

       --given-name=GIVEN_NAME
           Contact's given name.

       --initials=INITIALS
           Contact's initials.

       --display-name=DISPLAY_NAME
           Contact's display name.

       --job-title=JOB_TITLE
           Contact's job title.

       --department=DEPARTMENT
           Contact's department.

       --company=COMPANY
           Contact's company.

       --mail-address=MAIL_ADDRESS
           Contact's email address.

       --internet-address=INTERNET_ADDRESS
           Contact's home page.

       --telephone-number=TELEPHONE_NUMBER
           Contact's phone number.

       --mobile-number=MOBILE_NUMBER
           Contact's mobile phone number.

       --physical-delivery-office=PHYSICAL_DELIVERY_OFFICE
           Contact's office location.

   contact create [contactname] [options]
       Add a new contact. This is a synonym for the samba-tool contact add command and is available for compatibility reasons only. Please use
       samba-tool contact add instead.

   contact delete contactname [options]
       Delete an existing contact.

       The contactname specified on the command is the common name or the distinguished name of the contact object. The distinguished name of the
       contact can be specified with or without the domainDN component.

   contact edit contactname
       Modify a contact AD object.

       The contactname specified on the command is the common name or the distinguished name of the contact object. The distinguished name of the
       contact can be specified with or without the domainDN component.

       --editor=EDITOR
           Specifies the editor to use instead of the system default, or 'vi' if no system default is set.

   contact list [options]
       List all contacts.

       --full-dn
           Display contact's full DN instead of the name.

   contact move contactname new_parent_dn [options]
       This command moves a contact into the specified organizational unit or container.

       The contactname specified on the command is the common name or the distinguished name of the contact object. The distinguished name of the
       contact can be specified with or without the domainDN component.

   contact show contactname [options]
       Display a contact AD object.

       The contactname specified on the command is the common name or the distinguished name of the contact object. The distinguished name of the
       contact can be specified with or without the domainDN component.

       --attributes=CONTACT_ATTRS
           Comma separated list of attributes, which will be printed.

   contact rename contactname [options]
       Rename a contact and related attributes.

       This command allows to set the contact's name related attributes. The contact's CN will be renamed automatically. The contact's new CN will be
       made up by combining the given-name, initials and surname. A dot ('.') will be appended to the initials automatically, if required. Use the
       --force-new-cn option to specify the new CN manually and --reset-cn to reset this change.

       Use an empty attribute value to remove the specified attribute.

       The contact name specified on the command is the CN.

       --surname=SURNAME
           New surname.

       --given-name=GIVEN_NAME
           New given name.

       --initials=INITIALS
           New initials.

       --force-new-cn=NEW_CN
           Specify a new CN (RDN) instead of using a combination of the given name, initials and surname.

       --reset-cn
           Set the CN to the default combination of given name, initials and surname.

       --display-name=DISPLAY_NAME
           New display name.

       --mail-address=MAIL_ADDRESS
           New email address.

   dbcheck
       Check the local AD database for errors.

   delegation
       Manage Delegations.

   delegation add-service accountname principal [options]
       Add a service principal as msDS-AllowedToDelegateTo.

   delegation del-service accountname principal [options]
       Delete a service principal as msDS-AllowedToDelegateTo.

   delegation for-any-protocol accountname [(on|off)] [options]
       Set/unset UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION (S4U2Proxy) for an account.

   delegation for-any-service accountname [(on|off)] [options]
       Set/unset UF_TRUSTED_FOR_DELEGATION for an account.

   delegation show accountname [options]
       Show the delegation setting of an account.

   dns
       Manage Domain Name Service (DNS).

   dns add server zone name A|AAAA|PTR|CNAME|NS|MX|SRV|TXT data
       Add a DNS record.

   dns delete server zone name A|AAAA|PTR|CNAME|NS|MX|SRV|TXT data
       Delete a DNS record.

   dns query server zone name A|AAAA|PTR|CNAME|NS|MX|SRV|TXT|ALL [options] data
       Query a name.

   dns roothints server [name] [options]
       Query root hints.

   dns serverinfo server [options]
       Query server information.

   dns update server zone name A|AAAA|PTR|CNAME|NS|MX|SRV|TXT olddata newdata
       Update a DNS record.

   dns zonecreate server zone [options]
       Create a zone.

   dns zonedelete server zone [options]
       Delete a zone.

   dns zoneinfo server zone [options]
       Query zone information.

   dns zonelist server [options]
       List zones.

   domain
       Manage Domain.

   domain backup
       Create or restore a backup of the domain.

   domain backup offline
       Backup (with proper locking) local domain directories into a tar file.

   domain backup online
       Copy a running DC's current DB into a backup tar file.

   domain backup rename
       Copy a running DC's DB to backup file, renaming the domain in the process.

   domain backup restore
       Restore the domain's DB from a backup-file.

   domain auth policy
       Manage authentication policies.

   domain auth policy list
       List authentication policies on the domain.

       -H, --URL
           LDB URL for database or target server.

       --json
           View authentication policies as JSON instead of a list.

   domain auth policy view
       View an authentication policy on the domain.

       -H, --URL
           LDB URL for database or target server.

       --name
           Name of the authentication policy to view (required).

   domain auth policy create
       Create authentication policies on the domain.

       -H, --URL
           LDB URL for database or target server.

       --name
           Name of the authentication policy (required).

       --description
           Optional description for the authentication policy.

       --protect
           Protect authentication policy from accidental deletion.

           Cannot be used together with --unprotect.

       --unprotect
           Unprotect authentication policy from accidental deletion.

           Cannot be used together with --protect.

       --audit
           Only audit authentication policy.

           Cannot be used together with --enforce.

       --enforce
           Enforce authentication policy.

           Cannot be used together with --audit.

       --strong-ntlm-policy
           Strong NTLM Policy (Disabled, Optional, Required).

       --user-tgt-lifetime-mins
           Ticket-Granting-Ticket lifetime for user accounts.

       --user-allow-ntlm-auth
           Allow NTLM and
            Interactive NETLOGON SamLogon authentication despite the fact that allowed-to-authenticate-from is in use, which would otherwise restrict
           the user to selected devices.

       --user-allowed-to-authenticate-from
           Conditions a device must meet for users covered by this policy to be allowed to authenticate. While this is a restriction on the device,
           any conditional ACE rules are expressed as if the device was a user.

           Must be a valid SDDL string without reference to Device keywords.

           Example: O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(AU)}))

       --user-allowed-to-authenticate-to=SDDL
           This policy, applying to a user account that is offering a service, eg a web server with a user account, restricts which accounts may
           access it.

           Must be a valid SDDL string. The SDDL can reference both bare (user) and Device conditions.

           SDDL Example: O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(AO)}))

       --service-tgt-lifetime-mins
           Ticket-Granting-Ticket lifetime for service accounts.

       --service-allow-ntlm-auth
           Allow NTLM network authentication when service is restricted to selected devices.

       --service-allowed-to-authenticate-from
           Conditions a device must meet for service accounts covered by this policy to be allowed to authenticate. While this is a restriction on
           the device, any conditional ACE rules are expressed as if the device was a user.

           Must be a valid SDDL string without reference to Device keywords.

           SDDL Example: O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(AU)}))

       --service-allowed-to-authenticate-to=SDDL
           This policy, applying to a service account (eg a Managed Service Account, Group Managed Service Account), restricts which accounts may
           access it.

           Must be a valid SDDL string. The SDDL can reference both bare (user) and Device conditions.

           SDDL Example: O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(AO)}))

       --computer-tgt-lifetime-mins
           Ticket-Granting-Ticket lifetime for computer accounts.

       --computer-allowed-to-authenticate-to=SDDL
           This policy, applying to a computer account (eg a server or workstation), restricts which accounts may access it.

           Must be a valid SDDL string. The SDDL can reference both bare (user) and Device conditions.

           SDDL Example: O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(AO)}))

   domain auth policy modify
       Modify authentication policies on the domain. The same options apply as for domain auth policy create.

   domain auth policy delete
       Delete authentication policies on the domain.

       -H, --URL
           LDB URL for database or target server.

       --name
           Name of authentication policy to delete (required).

       --force
           Force authentication policy delete even if it is protected.

   domain auth policy user-allowed-to-authenticate-from set
       Set the user-allowed-to-authenticate-from property by scenario.

       -H, --URL
           LDB URL for database or target server.

       --name
           Name of authentication policy.

       --by-group=GROUP
           User is allowed to authenticate, if the device they authenticate from is assigned and granted membership of a given GROUP.

       --silo=SILO
           User is allowed to authenticate, if the device they authenticate from is assigned and granted membership of a given SILO.

   domain auth policy user-allowed-to-authenticate-to set
       Set the user-allowed-to-authenticate-to property by scenario.

       -H, --URL
           LDB URL for database or target server.

       --name
           Name of authentication policy.

       --group=GROUP
           The user account, offering a network service, covered by this policy, will only be allowed access from other accounts that are members of
           the given GROUP.

       --silo=SILO
           The user account, offering a network service, covered by this policy, will only be allowed access from other accounts that are assigned
           to, granted membership of (and meet any authentication conditions of) the given SILO.

   domain auth policy service-allowed-to-authenticate-from set
       Set the service-allowed-to-authenticate-from property by scenario.

       -H, --URL
           LDB URL for database or target server.

       --name
           Name of authentication policy.

       --group=GROUP
           The service account (eg a Managed Service Account, Group Managed Service Account) is allowed to authenticate, if the device it
           authenticates from is a member of the given GROUP.

       --silo=SILO
           The service account (eg a Managed Service Account, Group Managed Service Account) is allowed to authenticate, if the device it
           authenticates from is assigned and granted membership of a given SILO.

   domain auth policy service-allowed-to-authenticate-to set
       Set the service-allowed-to-authenticate-to property by scenario.

       -H, --URL
           LDB URL for database or target server.

       --name
           Name of authentication policy.

       --group=GROUP
           The service account (eg a Managed Service Account, Group Managed Service Account), will only be allowed access by other accounts that are
           members of the given GROUP.

       --silo=SILO
           The service account (eg a Managed Service Account, Group Managed Service Account), will only be allowed access by other accounts that are
           assigned to, granted membership of (and meet any authentication conditions of) the given SILO.

   domain auth policy computer-allowed-to-authenticate-to set
       Set the computer-allowed-to-authenticate-to property by scenario.

       -H, --URL
           LDB URL for database or target server.

       --name
           Name of authentication policy.

       --group=GROUP
           The computer account (eg a server or workstation), will only be allowed access by other accounts that are members of the given GROUP.

       --silo=SILO
           The computer account (eg a server or workstation), will only be allowed access by other accounts that are assigned to, granted membership
           of (and meet any authentication conditions of) the given SILO.

   domain auth silo
       Manage authentication silos.

   domain auth silo list
       List authentication silos on the domain.

       -H, --URL
           LDB URL for database or target server.

       --json
           View authentication silos as JSON instead of a list.

   domain auth silo view
       View an authentication silo on the domain.

       -H, --URL
           LDB URL for database or target server.

       --name
           Name of the authentication silo to view (required).

   domain auth silo create
       Create authentication silos on the domain.

       -H, --URL
           LDB URL for database or target server.

       --name
           Name of the authentication silo (required).

       --description
           Optional description for the authentication silo.

       --user-authentication-policy
           User account authentication policy.

       --service-authentication-policy
           Managed service account authentication policy.

       --computer-authentication-policy
           Computer authentication policy.

       --protect
           Protect authentication silo from accidental deletion.

           Cannot be used together with --unprotect.

       --unprotect
           Unprotect authentication silo from accidental deletion.

           Cannot be used together with --protect.

       --audit
           Only audit silo policies.

           Cannot be used together with --enforce.

       --enforce
           Enforce silo policies.

           Cannot be used together with --audit.

   domain auth silo modify
       Modify authentication silos on the domain.

       -H, --URL
           LDB URL for database or target server.

       --name
           Name of the authentication silo (required).

       --description
           Optional description for the authentication silo.

       --user-authentication-policy
           User account authentication policy.

       --service-authentication-policy
           Managed service account authentication policy.

       --computer-authentication-policy
           Computer authentication policy.

       --protect
           Protect authentication silo from accidental deletion.

           Cannot be used together with --unprotect.

       --unprotect
           Unprotect authentication silo from accidental deletion.

           Cannot be used together with --protect.

       --audit
           Only audit silo policies.

           Cannot be used together with --enforce.

       --enforce
           Enforce silo policies.

           Cannot be used together with --audit.

   domain auth silo delete
       Delete authentication silos on the domain.

       -H, --URL
           LDB URL for database or target server.

       --name
           Name of authentication silo to delete (required).

       --force
           Force authentication silo delete even if it is protected.

   domain auth silo member grant
       Grant a member access to an authentication silo.

       -H, --URL
           LDB URL for database or target server.

       --name
           Name of authentication silo (required).

       --member
           Member to grant access to the silo (DN or account name).

   domain auth silo member list
       List members in an authentication silo.

       -H, --URL
           LDB URL for database or target server.

       --name
           Name of authentication silo (required).

       --json
           View members as JSON instead of a list.

   domain auth silo member revoke
       Revoke a member from an authentication silo.

       -H, --URL
           LDB URL for database or target server.

       --name
           Name of authentication silo (required).

       --member
           Member to revoke from the silo (DN or account name).

   domain claim claim-type list
       List claim types on the domain.

       -H, --URL
           LDB URL for database or target server.

       --json
           View claim types as JSON instead of a list.

   domain claim claim-type view
       View a single claim type on the domain.

       -H, --URL
           LDB URL for database or target server.

       --name
           Display name of claim type to view (required).

   domain claim claim-type create
       Create claim types on the domain.

       -H, --URL
           LDB URL for database or target server.

       --attribute
           Attribute of claim type to create (required).

       --class
           Object classes to set claim type to.

           Example: --class=user --class=computer

       --name
           Optional display name or use attribute name.

       --description
           Optional description or use from attribute.

       --enable
           Enable claim type.

           Cannot be used together with --disable.

       --disable
           Disable claim type.

           Cannot be used together with --enable.

       --protect
           Protect claim type from accidental deletion.

           Cannot be used together with --unprotect.

       --unprotect
           Unprotect claim type from accidental deletion.

           Cannot be used together with --protect.

   domain claim claim-type modify
       Modify claim types on the domain.

       -H, --URL
           LDB URL for database or target server.

       --name
           Display name of claim type to modify (required).

       --class
           Object classes to set claim type to.

           Example: --class=user --class=computer

       --description
           Set the claim type description.

       --enable
           Enable claim type.

           Cannot be used together with --disable.

       --disable
           Disable claim type.

           Cannot be used together with --enable.

       --protect
           Protect claim type from accidental deletion.

           Cannot be used together with --unprotect.

       --unprotect
           Unprotect claim type from accidental deletion.

           Cannot be used together with --protect.

   domain claim claim-type delete
       Delete claim types on the domain.

       -H, --URL
           LDB URL for database or target server.

       --name
           Display name of claim type to delete (required).

       --force
           Force claim type delete even if it is protected.

   domain claim value-type list
       List claim value types on the domain.

       -H, --URL
           LDB URL for database or target server.

       --json
           View claim value types as JSON instead of a list.

   domain claim value-type view
       View a single claim value type on the domain.

       -H, --URL
           LDB URL for database or target server.

       --name
           Display name of claim value type to view (required).

   service-account
       Service account management.

   service-account list
       List service accounts on the domain.

       -H, --URL
           LDB URL for database or target server.

       --json
           View service accounts as JSON instead of a list.

   service-account view
       View a single service account on the domain.

       -H, --URL
           LDB URL for database or target server.

       --name
           Account name of service account to view (required).

   service-account create
       Create a new service account on the domain.

       -H, --URL
           LDB URL for database or target server.

       --name
           Account name of service account (required).

       --dns-host-name
           DNS hostname of this service account (required).

       --group-msa-membership
           Optional Group MSA Membership SDDL.

       --managed-password-interval
           Managed password refresh interval in days.

   service-account modify
       Modify an existing service account on the domain.

       -H, --URL
           LDB URL for database or target server.

       --name
           Account name of service account (required).

       --dns-host-name
           Update DNS hostname of this service account.

       --group-msa-membership
           Update Group MSA Membership SDDL.

   service-account delete
       Delete a service accounts on the domain.

       -H, --URL
           LDB URL for database or target server.

       --name
           Account name of service account to delete.

   service-account group-msa-membership
       Service account Group MSA Membership management.

   service-account group-msa-membership show
       Display Group MSA Membership for a service account.

       -H, --URL
           LDB URL for database or target server.

       --name
           Account name of service account (required).

       --json
           Return as JSON instead of a list.

   service-account group-msa-membership add
       Add a principal to Group MSA Membership for a service account.

       -H, --URL
           LDB URL for database or target server.

       --name
           Account name of service account (required).

       --principal
           Name, DN or SID of principal to add.

   service-account group-msa-membership remove
       Remove a principal from Group MSA Membership for a service account.

       -H, --URL
           LDB URL for database or target server.

       --name
           Account name of service account (required).

       --principal
           Name, DN or SID of principal to remove.

   domain classicupgrade [options] classic_smb_conf
       Upgrade from Samba classic (NT4-like) database to Samba AD DC database.

   domain dcpromo dnsdomain [DC|RODC] [options]
       Promote an existing domain member or NT4 PDC to an AD DC.

   domain demote
       Demote ourselves from the role of domain controller.

   domain exportkeytab keytab [options]
       Dumps Kerberos keys of the domain into a keytab.

   domain info ip_address [options]
       Print basic info about a domain and the specified DC.

   domain join dnsdomain [DC|RODC|MEMBER|SUBDOMAIN] [options]
       Join a domain as either member or backup domain controller.

   domain level show|raise options [options]
       Show/raise domain and forest function levels.

   domain passwordsettings show|set options [options]
       Show/set password settings.

   domain passwordsettings pso
       Manage fine-grained Password Settings Objects (PSOs).

   domain passwordsettings pso apply pso-name user-or-group-name [options]
       Applies a PSO's password policy to a user or group.

   domain passwordsettings pso create pso-name precedence [options]
       Creates a new Password Settings Object (PSO).

   domain passwordsettings pso delete pso-name [options]
       Deletes a Password Settings Object (PSO).

   domain passwordsettings pso list [options]
       Lists all Password Settings Objects (PSOs).

   domain passwordsettings pso set pso-name [options]
       Modifies a Password Settings Object (PSO).

   domain passwordsettings pso show user-name [options]
       Displays a Password Settings Object (PSO).

   domain passwordsettings pso show-user pso-name [options]
       Displays the Password Settings that apply to a user.

   domain passwordsettings pso unapply pso-name user-or-group-name [options]
       Updates a PSO to no longer apply to a user or group.

   domain provision
       Promote an existing domain member or NT4 PDC to an AD DC.

   domain trust
       Domain and forest trust management.

   domain trust create DOMAIN options [options]
       Create a domain or forest trust.

   domain trust modify DOMAIN options [options]
       Modify a domain or forest trust.

   domain trust delete DOMAIN options [options]
       Delete a domain trust.

   domain trust list options [options]
       List domain trusts.

   domain trust namespaces [DOMAIN] options [options]
       Manage forest trust namespaces.

   domain trust show DOMAIN options [options]
       Show trusted domain details.

   domain trust validate DOMAIN options [options]
       Validate a domain trust.

   drs
       Manage Directory Replication Services (DRS).

   drs bind
       Show DRS capabilities of a server.

   drs kcc
       Trigger knowledge consistency center run.

   drs options
       Query or change options for NTDS Settings object of a domain controller.

   drs replicate destination_DC source_DC NC [options]
       Replicate a naming context between two DCs.

   drs showrepl
       Show replication status. The [--json] option results in JSON output, and with the [--summary] option produces very little output when the
       replication status seems healthy.

   dsacl
       Administer DS ACLs

   dsacl delete
       Delete an access list entry on a directory object.

   dsacl get
       Print access list on a directory object.

   dsacl set
       Modify access list on a directory object.

   forest
       Manage Forest configuration.

   forest directory_service
       Manage directory_service behaviour for the forest.

   forest directory_service dsheuristics VALUE
       Modify dsheuristics directory_service configuration for the forest.

   forest directory_service show
       Show current directory_service configuration for the forest.

   fsmo
       Manage Flexible Single Master Operations (FSMO).

   fsmo seize [options]
       Seize the role.

   fsmo show
       Show the roles.

   fsmo transfer [options]
       Transfer the role.

   gpo
       Manage Group Policy Objects (GPO).

   gpo create displayname [options]
       Create an empty GPO.

   gpo del gpo [options]
       Delete GPO.

   gpo dellink container_dn gpo [options]
       Delete GPO link from a container.

   gpo fetch gpo [options]
       Download a GPO.

   gpo getinheritance container_dn [options]
       Get inheritance flag for a container.

   gpo getlink container_dn [options]
       List GPO Links for a container.

   gpo list username [options]
       List GPOs for an account.

   gpo listall
       List all GPOs.

   gpo listcontainers gpo [options]
       List all linked containers for a GPO.

   gpo setinheritance container_dn block|inherit [options]
       Set inheritance flag on a container.

   gpo setlink container_dn gpo [options]
       Add or Update a GPO link to a container.

   gpo show gpo [options]
       Show information for a GPO.

   gpo manage symlink list
       List VGP Symbolic Link Group Policy from the sysvol

   gpo manage symlink add
       Adds a VGP Symbolic Link Group Policy to the sysvol

   gpo manage symlink remove
       Removes a VGP Symbolic Link Group Policy from the sysvol

   gpo manage files list
       List VGP Files Group Policy from the sysvol

   gpo manage files add
       Add VGP Files Group Policy to the sysvol

   gpo manage files remove
       Remove VGP Files Group Policy from the sysvol

   gpo manage openssh list
       List VGP OpenSSH Group Policy from the sysvol

   gpo manage openssh set
       Sets a VGP OpenSSH Group Policy to the sysvol

   gpo manage sudoers add
       Adds a Samba Sudoers Group Policy to the sysvol.

   gpo manage sudoers list
       List Samba Sudoers Group Policy from the sysvol.

   gpo manage sudoers remove
       Removes a Samba Sudoers Group Policy from the sysvol.

   gpo manage scripts startup list
       List VGP Startup Script Group Policy from the sysvol

   gpo manage scripts startup add
       Adds VGP Startup Script Group Policy to the sysvol

   gpo manage scripts startup remove
       Removes VGP Startup Script Group Policy from the sysvol

   gpo manage motd list
       List VGP MOTD Group Policy from the sysvol.

   gpo manage motd set
       Sets a VGP MOTD Group Policy to the sysvol

   gpo manage issue list
       List VGP Issue Group Policy from the sysvol.

   gpo manage issue set
       Sets a VGP Issue Group Policy to the sysvol

   gpo manage access add
       Adds a VGP Host Access Group Policy to the sysvol

   gpo manage access list
       List VGP Host Access Group Policy from the sysvol

   gpo manage access remove
       Remove a VGP Host Access Group Policy from the sysvol

   group
       Manage groups.

   group add groupname [options]
       Create a new AD group.

   group create groupname [options]
       Add a new AD group. This is a synonym for the samba-tool group add command and is available for compatibility reasons only. Please use
       samba-tool group add instead.

   group addmembers groupname members [options]
       Add members to an AD group.

   group delete groupname [options]
       Delete an AD group.

   group edit groupname
       Edit a group AD object.

       --editor=EDITOR
           Specifies the editor to use instead of the system default, or 'vi' if no system default is set.

   group list
       List all groups.

   group listmembers groupname [options]
       List all members of the specified AD group.

       By default the sAMAccountNames are listed. If no sAMAccountName is available, the CN will be used instead.

       --full-dn
           List the distinguished names instead of the sAMAccountNames.

       --hide-expired
           Do not list expired group members.

       --hide-disabled
           Do not list disabled group members.

   group move groupname new_parent_dn [options]
       This command moves a group into the specified organizational unit or container.

       The groupname specified on the command is the sAMAccountName.

       The name of the organizational unit or container can be specified as a full DN or without the domainDN component.

   group removemembers groupname members [options]
       Remove members from the specified AD group.

   group show groupname [options]
       Show group object and it's attributes.

   group stats [options]
       Show statistics for overall groups and group memberships.

   group rename groupname [options]
       Rename a group and related attributes.

       This command allows to set the group's name related attributes. The group's CN will be renamed automatically. The group's CN will be the
       sAMAccountName. Use the --force-new-cn option to specify the new CN manually and the --reset-cn to reset this change.

       Use an empty attribute value to remove the specified attribute.

       The groupname specified on the command is the sAMAccountName.

       --force-new-cn=NEW_CN
           Specify a new CN (RDN) instead of using the sAMAccountName.

       --reset-cn
           Set the CN to the sAMAccountName.

       --mail-address=MAIL_ADDRESS
           New mail address

       --samaccountname=SAMACCOUNTNAME
           New account name (sAMAccountName/logon name)

   ldapcmp URL1 URL2 domain|configuration|schema|dnsdomain|dnsforest [options]
       Compare two LDAP databases.

   ntacl
       Manage NT ACLs.

   ntacl changedomsid original-domain-SID new-domain-SID file [options]
       Change the domain SID for ACLs. Can be used to change all entries in acl_xattr when the machine's SID has accidentally changed or the data set
       has been copied to another machine either via backup/restore or rsync.

       --use-ntvfs
           Set the ACLs directly to the TDB or xattr. The POSIX permissions will NOT be changed, only the NT ACL will be stored.

       --service=SERVICE
           Specify the name of the smb.conf service to use. This option is required in combination with the --use-s3fs option.

       --use-s3fs
           Set the ACLs for use with the default s3fs file server via the VFS layer. This option requires a smb.conf service, specified by the
           --service=SERVICE option.

       --xattr-backend=[native|tdb]
           Specify the xattr backend type (native fs or tdb).

       --eadb-file=EADB_FILE
           Name of the tdb file where attributes are stored.

       --recursive
           Set the ACLs for directories and their contents recursively.

       --follow-symlinks
           Follow symlinks when --recursive is specified.

       --verbose
           Verbosely list files and ACLs which are being processed.

   ntacl get file [options]
       Get ACLs on a file.

   ntacl set acl file [options]
       Set ACLs on a file.

   ntacl sysvolcheck
       Check sysvol ACLs match defaults (including correct ACLs on GPOs).

   ntacl sysvolreset
       Reset sysvol ACLs to defaults (including correct ACLs on GPOs).

   ou
       Manage organizational units (OUs).

   ou add ou_dn [options]
       Add a new organizational unit.

       The name of the organizational unit can be specified as a full DN or without the domainDN component.

       --description=DESCRIPTION
           Specify OU's description.

   ou create ou_dn [options]
       Add a new organizational unit. This is a synonym for the samba-tool ou add command and is available for compatibility reasons only. Please use
       samba-tool ou add instead.

   ou delete ou_dn [options]
       Delete an organizational unit.

       The name of the organizational unit can be specified as a full DN or without the domainDN component.

       --force-subtree-delete
           Delete organizational unit and all children recursively.

   ou list [options]
       List all organizational units.

       --full-dn
           Display DNs including the base DN.

   ou listobjects ou_dn [options]
       List all objects in an organizational unit.

       The name of the organizational unit can be specified as a full DN or without the domainDN component.

       --full-dn
           Display DNs including the base DN.

       -r|--recursive
           List objects recursively.

   ou move old_ou_dn new_parent_dn [options]
       Move an organizational unit.

       The name of the organizational units can be specified as a full DN or without the domainDN component.

   ou rename old_ou_dn new_ou_dn [options]
       Rename an organizational unit.

       The name of the organizational units can be specified as a full DN or without the domainDN component.

   rodc
       Manage Read-Only Domain Controller (RODC).

   rodc preload SID|DN|accountname [options]
       Preload one account for an RODC.

   schema
       Manage and query schema.

   schema attribute modify attribute [options]
       Modify the behaviour of an attribute in schema.

   schema attribute show attribute [options]
       Display an attribute schema definition.

   schema attribute show_oc attribute [options]
       Show objectclasses that MAY or MUST contain this attribute.

   schema objectclass show objectclass [options]
       Display an objectclass schema definition.

   shell
       Opens an interactive Samba Python shell.

   shell [options]
       Opens an interactive Python shell for Samba ldb connection.

       -H, --URL
           LDB URL for database or target server.

   sites
       Manage sites.

   sites list [options]
       List sites.

       --json
           Output as JSON instead of a list

   sites view site [options]
       View site details.

   sites create site [options]
       Create a new site.

   sites remove site [options]
       Delete an existing site.

   sites subnet list site [options]
       List subnets for a site.

       --json
           Output as JSON instead of a list

   sites subnet view subnet [options]
       View subnet details.

   sites subnet create subnet site-of-subnet [options]
       Create a new subnet.

   sites subnet remove subnet [options]
       Delete an existing subnet.

   sites subnet set-site subnet site-of-subnet [options]
       Assign a subnet to a site.

   spn
       Manage Service Principal Names (SPN).

   spn add name user [options]
       Create a new SPN.

   spn delete name [user] [options]
       Delete an existing SPN.

   spn list user [options]
       List SPNs of a given user.

   testparm
       Check the syntax of the configuration file.

   time
       Retrieve the time on a server.

   user
       Manage users.

   user add username [password]
       Add a new user to the Active Directory Domain.

   user create username [password]
       Add a new user. This is a synonym for the samba-tool user add command and is available for compatibility reasons only. Please use samba-tool
       user add instead.

   user delete username [options]
       Delete an existing user account.

   user disable username
       Disable a user account.

   user edit username
       Edit a user account AD object.

       --editor=EDITOR
           Specifies the editor to use instead of the system default, or 'vi' if no system default is set.

   user enable username
       Enable a user account.

   user list
       List all users.

       By default the user's sAMAccountNames are listed.

       --full-dn
           List user's distinguished names instead of the sAMAccountNames.

       -b BASE_DN|--base-dn=BASE_DN
           Specify base DN to use. Only users under the specified base DN will be listed.

       --hide-expired
           Do not list expired user accounts.

       --hide-disabled
           Do not list disabled user accounts.

       --locked-only
           Only list locked user accounts.

   user setprimarygroup username primarygroupname
       Set the primary group a user account.

   user getgroups username
       Get the direct group memberships of a user account.

   user show username [options]
       Display a user AD object.

       --attributes=USER_ATTRS
           Comma separated list of attributes, which will be printed.

   user move username new_parent_dn [options]
       This command moves a user account into the specified organizational unit or container.

       The username specified on the command is the sAMAccountName.

       The name of the organizational unit or container can be specified as a full DN or without the domainDN component.

   user password [options]
       Change password for a user account (the one provided in authentication).

   user rename username [options]
       Rename a user and related attributes.

       This command allows to set the user's name related attributes. The user's CN will be renamed automatically. The user's new CN will be made up
       by combining the given-name, initials and surname. A dot ('.') will be appended to the initials automatically, if required. Use the
       --force-new-cn option to specify the new CN manually and --reset-cn to reset this change.

       Use an empty attribute value to remove the specified attribute.

       The username specified on the command is the sAMAccountName.

       --surname=SURNAME
           New surname

       --given-name=GIVEN_NAME
           New given name

       --initials=INITIALS
           New initials

       --force-new-cn=NEW_CN
           Specify a new CN (RDN) instead of using a combination of the given name, initials and surname.

       --reset-cn
           Set the CN to the default combination of given name, initials and surname.

       --display-name=DISPLAY_NAME
           New display name

       --mail-address=MAIL_ADDRESS
           New email address

       --samaccountname=SAMACCOUNTNAME
           New account name (sAMAccountName/logon name)

       --upn=UPN
           New user principal name

   user setexpiry username [options]
       Set the expiration of a user account.

   user setpassword username [options]
       Sets or resets the password of a user account.

   user unlock username [options]
       This command unlocks a user account in the Active Directory domain.

   user getpassword username [options]
       Gets the password of a user account.

   user get-kerberos-ticket username [options]
       Gets a Kerberos Ticket Granting Ticket as the account.

   user syncpasswords --cache-ldb-initialize [options]
       Syncs the passwords of all user accounts, using an optional script.

       Note that this command should run on a single domain controller only (typically the PDC-emulator).

   user auth policy assign username [options]
       Set assigned authentication policy for user.

       --policy
           Name of authentication policy to assign or leave empty to remove.

   user auth policy remove username
       Remove assigned authentication policy from user.

   user auth policy view username
       View the assigned authentication policy for user.

   user auth silo assign username [options]
       Set assigned authentication silo for user.

       --silo
           Name of authentication silo to assign or leave empty to remove.

   user auth silo remove username
       Remove assigned authentication silo from user.

   user auth silo view username
       View the assigned authentication silo for user.

   vampire [options] domain
       Join and synchronise a remote AD domain to the local server. Please note that samba-tool vampire is deprecated, please use samba-tool domain
       join instead.

   visualize [options] subcommand
       Produce graphical representations of Samba network state. To work out what is happening in a replication graph, it is sometimes helpful to use
       visualisations.

       There are two subcommands, two graphical modes, and (roughly) two modes of operation with respect to the location of authority.

   MODES OF OPERATION
       samba-tool visualize ntdsconn
           Looks at NTDS connections.

       samba-tool visualize reps
           Looks at repsTo and repsFrom objects.

       samba-tool visualize uptodateness
           Looks at replication lag as shown by the uptodateness vectors.

   GRAPHICAL MODES
       --distance
           Distances between DCs are shown in a matrix in the terminal.

       --dot
           Generate Graphviz dot output (for ntdsconn and reps modes). When viewed using dot or xdot, this shows the network as a graph with DCs as
           vertices and connections edges. Certain types of degenerate edges are shown in different colours or line-styles.

       --xdot
           Generate Graphviz dot output as with [--dot] and attempt to view it immediately using /usr/bin/xdot.

       -r
           Normally, samba-tool talks to one database; with the [-r] option attempts are made to contact all the DCs known to the first database.
           This is necessary for samba-tool visualize uptodateness and for samba-tool visualize reps because the repsFrom/To objects are not
           replicated, and it can reveal replication issues in other modes.

   help
       Gives usage information.

VERSION
       This man page is complete for version 4.21.9-alt1 of the Samba suite.

AUTHOR
       The original Samba software and related utilities were created by Andrew Tridgell. Samba is now developed by the Samba Team as an Open Source
       project similar to the way the Linux kernel is developed.

Samba 4.21.9-alt1                                                     10/24/2025                                                        SAMBA-TOOL(8)
