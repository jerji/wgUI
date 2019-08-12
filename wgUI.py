#! /usr/bin/python3
import string
import subprocess
import os
import ipaddress
import re
import sys

configFile = 'example1.conf'

clear = lambda: os.system('clear')

### readCfg(Input file)
### Read configuration file and return config as dictionary
def readCfg(input):
    # open the file
    file = open(input,'r')

    # create an empty dict
    sections = {}
    # number so each is unique
    i = 0
    for line in file.readlines():
        deadline = 0
        # get rid of the newline
        line = line[:-1]
        # this will break if you have whitespace on the "blank" lines
        if line:

            # this assumes everything starts on the first column
            if line[0] == '[':
                # strip the brackets
                section = line[1:-1] + str(i)
                # create a new section if it doesn't already exist
                if not section in sections:
                    sections[section] = {}
                    i=i+1
            else:

                # split on first the equal sign
                if '=' in line:
                    (key, val) = line.split('=', 1)
                else:
                    deadline = 1

                # create the attribute as a list if it doesn't
                # exist under the current section, this will
                # break if there's no section set yet
                if not deadline:
                    if not key.strip() in sections[section]:
                        sections[section][key.strip()] = []

                        # append the new value to the list
                        sections[section][key.strip()].append(val.strip())

    file.close()
    return(sections)

### genUsrCfg(Vpn address of client, Private key of client, Dns Server, Public key of the server,
###           Server Preshared Key, Allowed IPs, IP of the server, Delay of persistent keepalive )
### Generates a User config and returns a dictionary with the config.
def genUsrCfg(localHost, privKey, dns, serverPub, AllowedIPs, serverIP, PersistentKeepalive):
    #Create an empty dict for the complete config
    config = {}
    #Create empty dict for interface section
    interface = {}
    #Setting the keys to the right values
    interface['Address'] = [localHost]
    interface['PrivateKey'] = [privKey]
    if dns != '':
        interface['DNS'] = [dns]
    #Adding to the config
    config['Interface'] = interface

    #Create empty dict for peer section
    peer = {}
    #Setting the keys to the right values
    peer['PublicKey'] = [serverPub]
    peer['AllowedIPs'] = [AllowedIPs]
    peer['Endpoint'] = [serverIP]
    if PersistentKeepalive != '':
        peer['PersistentKeepalive'] = [PersistentKeepalive]
    #Adding to the config
    config['Peer'] = peer
    return(config)

### writeCfg( Output file, Dictionary )
### Take dictionary as input and write to config file.
def writeCfg(output, sections):
    #Create/overwrite file
    file = open(output, 'w')
    #Convert the dictionary to the config
    conf = dictToConf(sections)
    #Write the file
    file.write(conf)
    file.close()
    restartVPN()

### dictToConf(Dictionary of config)
### Takes a dictionary config as input and makes it into a config as a string
def dictToConf(sections):
    #Define a buffer to put the conf in
    conf = ''

    for section in sections:
        #Strip digits
        unnum = section.rstrip(string.digits)
        #Add brackets
        conf += '['+unnum+']\n'
        for key in sections[section]:
            #Write the keys to the buffer
            conf += str(key) + ' = ' + ''.join(sections[section][key][0])+'\n'
        conf += '\n'
    return(conf)

###listEntries(Dictionary to list entries from)
###List the entries in the config
def listEntries(sections):
    for section in sections:
        #List keys in section
        if 'Peer' in section:
            print('Name: '+ ''.join(sections[section]['#Name']))
            print('    IP: '+ ''.join(sections[section]['AllowedIPs']))
            print('    Public Key: '+ ''.join(sections[section]['PublicKey']))
            if 'Endpoint' in sections[section]:
                print('    Last IP: '+ ''.join(sections[section]['Endpoint']))
            print('')

### addEntry(PublicKey, PresharedKey, AllowedIPs, Endpoint, PersistentKeepalive, Additional fields as dict, Dictionary to mod)
### Add entry to config file. Additional fields in a dictionary format, they must start with a "#" so wireguard ignores them
def addEntry(PublicKey, AllowedIPs, Endpoint, PersistentKeepalive, additional, sections):
    #Set the number at the end to the next number
    currentNum = len(sections)
    #Create an empty dict for the new entry
    entry = {}
    #Set all the keys to the right value
    entry['PublicKey'] = [PublicKey]
    entry['AllowedIPs'] = [AllowedIPs]
    if Endpoint != '':
        entry['Endpoint'] = [Endpoint]
    if PersistentKeepalive != '':
        entry['PersistentKeepalive'] = [PersistentKeepalive]
    #add additional info like the name and any other additional fields.
    if additional != '':
        entry.update(additional)
    #Add entry to the main dictionary.
    sections['Peer'+str(currentNum)] = entry
    return sections

### remEntry(name of user, Dictionary)
### Remove entry from config
def remEntry(name, sections):
    #Variable to check if we deleted anything
    isDelete = 0
    if not name == '':
        for section in sections:
            #Make sure we don't delete the interface part
            if 'Peer' in section:
            #Look at the name field
                if ''.join(sections[section]['#Name']) == name:
                    #Delete entry
                    del sections[section]
                    print('User ' + name + ' deleted.')
                    isDelete = 1
                    break

    if not isDelete: print('User ' + name + ' not found.')
    return sections

### renameEntry(Old name, New name, Dictionary)
### Rename entry from Old name to new name
def renameEntry(old, new, sections):
    isRenamed = 0
    if not old == '':
        for section in sections:
            if 'Peer' in section:
            #Look at the name field
                if ''.join(sections[section]['#Name']) == old:
                    #Rename entry
                    sections[section]['#Name'] = [new]
                    print('User ' + old + ' renamed to ' + new + '.')
                    isRenamed = 1
                    break

    if not isRenamed: print('User ' + name + ' not found.')
    return sections

### genKeys()
### Generate private and public keys as a list in format [Private, Public]
def genKeys():

    #First we run genkey to generate the private key.
    p = subprocess.run(['wg', 'genkey'], stdout=subprocess.PIPE)
    privKey = p.stdout.decode("ascii")

    #We then feed it in pupbkey to generate the public key.
    p = subprocess.run(['wg', 'pubkey'], stdout=subprocess.PIPE,input=privKey, encoding='ascii')
    pubKey = p.stdout
    return([privKey.rstrip(), pubKey.rstrip()])

### qrEncode(Input string)
### uses qrencode(1) to generate a qr code and output it to the console.
def qrEncode(input):
    #Launch qrencode
    p = subprocess.run(['qrencode', '-t', 'ANSIUTF8'], stdout=subprocess.PIPE,input=input, encoding='utf8')
    qr = p.stdout
    print(qr)

###findIP(Dictionary)
###Finds the first unused IP in the config file
def findIP(sections):

    #Get IP range
    range = sections['Interface0']['#ipRange'][0]
    #Transform into IP address object
    network = ipaddress.ip_network(range)
    #Create empy array for used Ips
    used = []

    for section in sections:
        if 'Peer' in section:
            #Append all the Ips from the pers to the array
            ipstr = ''.join(sections[section]['AllowedIPs'])
            ip = ipaddress.ip_address(ipstr.split('/')[0])
            used.append(ip)

    #In the list of all hosts for our IP range
    for ip in list(network.hosts()):
        #Look for one that hasn't been used
        if not ip in used:
            #Make sure the last number isnt 1
            if not int(str(ip).split('.')[3]) == 1:
                return str(ip) + '/32'
    if result == '':
        return 1

### checkIP(Ip address as string, bool subnet or not)
### Checks if the format of an IP is correct, optionally with the subnet
def checkIP(ip,s):
    if s:
        #Regex with subnet
        pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$")
    else:
        #Regex without subnet
        pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    return pat.match(ip)

### restartVPN()
### Restarts the wireguard VPN
def restartVPN():
    #Bring interface down
    p = subprocess.run(['wg-quick', 'down', '/etc/wireguard/'+ configFile ], stdout=subprocess.PIPE)
    #Bring interface up
    p = subprocess.run(['wg-quick', 'up', '/etc/wireguard/'+ configFile ], stdout=subprocess.PIPE)


#################
### UI Stuff  ###
#################

###Main menu
def main():
    if not os.getuid() == 0:
        print('Please run this script as root.')
        return 1
    isMenu = 1
    while isMenu:
        #Re-read config
        clear()
        sections = readCfg('/etc/wireguard/'+ configFile)

        #Check if all the fields are filled out
        if not '#Host' in sections['Interface0'] or not '#pubKey' in sections['Interface0'] or not '#ipRange' in sections['Interface0']:
            writeCfg('/etc/wireguard/'+ configFile, firstConfig(sections))
        #Check if the names are all filled out
        for section in sections:
            if 'Peer' in section and not '#Name' in sections[section]:
                print('Looks like there is an unnamed user in your config.')
                print('Press enter to go to the naming menu.')
                input('>')
                writeCfg('/etc/wireguard/'+ configFile, nameMenu(sections))

        #Main menu
        clear()
        print('Well hello! Welcome to the main menu!')
        print('This menu is used to generate Wireguard keys.')
        print('Please select an option:')
        print('')
        print('1 - List current users')
        print('2 - Add user to VPN')
        print('3 - Remove user from VPN')
        print('4 - Rename user')
        print('w - Re-launch setup wizard')
        print('5 - Exit')
        var = input('>')
        clear()

        #List user
        if var == "1":
            listEntries(sections)
            input('Press Enter to continue.')
        #Add user
        elif var == "2":
            #Go to the add menu
            new = addMenu(sections)
            #Make sure command didnt fail
            if not new == 1:
                #Write config
                writeCfg('/etc/wireguard/'+ configFile, new)
                print('User added.')
            else:
                print("Operation canceled.")
            input('Press Enter to continue.')
        #Remove user
        elif var == "3":
            #Print a list of all the names
            for section in sections:
                if 'Peer' in section:
                    print(''.join(sections[section]['#Name']))

            #ask for the name of the user
            print('\nPlease type the name of the user you would like to remove:')
            user = input('>')
            clear()

            #delete and write config
            writeCfg('/etc/wireguard/'+ configFile, remEntry(user, sections))
            input('Press Enter to continue.')
        #Rename user
        elif var == "4":
            renameMenu(sections)
        #Relaunch wizard
        elif var == "w":
            writeCfg('/etc/wireguard/'+ configFile, firstConfig(sections))
        #Exit
        elif var == "5":
            isMenu = 0
        else:
            print('Invalid menu option.\nPress Enter to continue.')
            input('>')

###renameMenu(Dictionary)
###Secondary menu for renaming a user
def renameMenu(sections):
    #Make an array of all used names
    names = []
    for section in sections:
        if 'Peer' in section:
            print(''.join(sections[section]['#Name']))
            names.append(sections[section]['#Name'][0])

    print('\nPlease type the name of the user you would like to rename:')
    #Makes sure that the name exists ang give multiple chances to get it right
    old = ''
    while old == '':
        old = input('>>')

        if old == '':
            clear()
            print("Operation canceled.")
            input('Press Enter to continue.')
            return

        elif not old in names:
            print('User does not exist.')
            old = ''

    clear()
    print('\nPlease type the new name for ' + old + ':')
    #Make sure that new name doesn't exist
    new = ''
    while new == '':
        new = input('>>')

        if new == '':
            clear()
            print("Operation canceled.")
            input('Press Enter to continue.')
            return

        if new in names:
            print('User exists.')
            new = ''

        if not new.isalnum():
            print('Invalid name')
            new = ''

    #Write config
    writeCfg('/etc/wireguard/'+ configFile, renameEntry(old, new, sections))
    input('Press Enter to continue.')

###addMenu(Dictionary)
###Secondary menu to add a user
def addMenu(sections):
    #Get all the needed parameters
    keys = genKeys()
    ip = findIP(sections)
    if ip == 1:
        print('Ran out of Ips.')
        print('Please increase IP range by re-running the setup wizard.')
        return 1
    pubServer = sections['Interface0']['#pubKey']
    serverIP = sections['Interface0']['#Host'][0] + ':' + sections['Interface0']['ListenPort'][0]
    names = []
    for section in sections:
        if 'Peer' in section:
            names.append(sections[section]['#Name'][0])
    #Start of menu
    user = input('Name of new user: ')
    if user == '':
        return 1
    if user in names:
        print('User exists')
        return 1
    if not user.isalnum():
        print('Invalid name')
        return 1
    keepalive = input('Keepalive(enter for none): ')
    if not keepalive.isdigit() and not keepalive == '':
        print('Value must be a number.')
        return 1
    dns = input('Dns server(enter for 1.1.1.1): ')
    if dns == '':
        dns = '1.1.1.1'
    elif not checkIP(dns, 0):
        print('Invalid dns server')
        return 1
    print('What type of vpn would you like: ')
    print('1 - Complete VPN')
    print('(2) - Remote local network')
    print('3 - Custom AllowedIPs field')
    choice = input('> ')
    if choice == '1':
        allowed = '0.0.0.0/0'
    elif choice == '2':
        allowed = sections['Interface0']['#ipRange'][0]
    elif choice == '3':
        tmp = input('>> ')
        if checkIP(tmp,1):
            allowed = tmp
        else:
            print('Invalid format.')
            return 1
    elif choice == '':
        allowed = sections['Interface0']['#ipRange'][0]
    else:
        return 1

    userconf = dictToConf(genUsrCfg(ip, keys[0],dns,pubServer,allowed,serverIP,keepalive))

    print('Would you like:')
    print('(1) - QR code')
    print('2 - Config parameters')
    choice = input('> ')
    if choice == '1':
        qrEncode(userconf)
    elif choice == '2':
        print(userconf)
    elif choice == '':
        qrEncode(userconf)
    else:
        return 1

    choice = input('Press enter to continue, "c" and then enter to cancel.')
    if choice == 'c':
        return 1
    clear()
    return addEntry(keys[1], ip, '', '', {'#Name': [user]}, sections)

###fisrtConfig(Dictionary)
###Setup Wizard
def firstConfig(sections):
    #Ask for IP or hostname of server
    print('Looks like it is the first time you use this tool!')
    print('I just need to know the IP or hostname and port of your server in format hostname:port')
    ip = ''
    while ip == '':
        ip = input('>>')
    #Ask for the IP range
    print('What is the IP range in format 0.0.0.0/0')
    range = ''
    while range == '':
        range = input('>>')
        #Make sure its a valid ip range
        if not checkIP(range,1):
            print('Invalid Range')
            range = ''
    #Derive public key
    privKey = sections['Interface0']['PrivateKey'][0]
    p = subprocess.run(['wg', 'pubkey'], stdout=subprocess.PIPE,input=privKey, encoding='ascii')
    pubKey = p.stdout
    #Set up values
    info = {'#Host': [ip], '#pubKey': [pubKey], '#ipRange': [range]}
    #Add to config file
    sections['Interface0'].update(info)

    #Name unnamed users
    print('What would you like to do with the users currently listed that have no name?')
    print('(1) - Assing random names to these users for now')
    print('2 - Set a name for each user')

    choice = input('> ')
    if choice == '1':
        sections = randomNames(sections)
    elif choice == '2':
        sections = nameMenu(sections)
    else:
        sections = randomNames(sections)

    clear()
    print('Setup wizard complete.')
    input('Press Enter to continue.')

    return sections

###randomNames(Dictionary)
###Rename unnamed users to User0..Usern
def randomNames(sections):
    i=0
    #Increment i and name each user to User(i)
    for section in sections:
        if 'Peer' in section and not '#Name' in sections[section]:
            info = {'#Name': ['User' + str(i)]}
            sections[section].update(info)
            i += 1
    return sections

###nameMenu(Dictionary)
###Secondary menu to name each user
def nameMenu(sections):

    #Array for names
    names = []

    #Add already used names to the array
    for section in sections:
        if 'Peer' in section and '#Name' in sections[section]:
            print(''.join(sections[section]['#Name']))
            names.append(sections[section]['#Name'][0])


    for section in sections:
        #If Peer is unnamed
        if 'Peer' in section and not '#Name' in sections[section]:

            clear()
            print('What would you like this user to be named?')
            print('')
            print('    IP: '+ ''.join(sections[section]['AllowedIPs']))
            print('    Public Key: '+ ''.join(sections[section]['PublicKey']))
            if 'Endpoint' in sections[section]:
                print('    Last IP: '+ ''.join(sections[section]['Endpoint']))
            print('')
            #Ask for name
            name = ''
            while name == '':
                name = input('>>')
                if name in names:
                    print('User exists')
                    name = ''
                if not name.isalnum():
                    print('Invalid name')
                    name = ''
            #Add name to name array
            names.append(name)
            info = {'#Name': [name]}
            #Add name field
            sections[section].update(info)

    return sections

##############################
### Non Interractive stuff ###
##############################

def ArgParse(sections):

    args = sys.argv()[1:]

    arg = args[1]
    if arg == 'add':
        argAdd(args[1:], sections)
    elif arg == 'list':
        argList(args[1:], sections)
    elif arg == 'remove':
        argRemove(args[1:], sections)
    elif arg == 'rename':
        argRename(args[1:], sections)
    elif arg == 'setup':
        argSetup(sections)
    elif arg == '-h':
        #TODO: Help
        sys.exit(0)
    else:
        return

def argAdd(args,sections):

    #Get all the needed parameters
    keys = genKeys()
    ip = findIP(sections)
    if ip == 1:
        print('Ran out of Ips.')
        print('Please increase IP range by re-running the setup wizard.')
        return 1
    pubServer = sections['Interface0']['#pubKey']
    serverIP = sections['Interface0']['#Host'][0] + ':' + sections['Interface0']['ListenPort'][0]
    names = []
    for section in sections:
        if 'Peer' in section:
            names.append(sections[section]['#Name'][0])
    #args: name,keepalive,dns,allowedIPs,file or console,qr or config
    sys.exit(0)

def argList(args,sections):
    listEntries(sections)
    sys.exit(0)

def argRemove(args,sections):
    #args: name of user
    sys.exit(0)

def argRename(args,sections):
    #args:currName, newName
    sys.exit(0)

def argSetup(args,sections):
    #args: ip:port, range,
    sys.exit(0)

if __name__ == '__main__': main()

# TODO: non-interactive mode, initial creation of config file
