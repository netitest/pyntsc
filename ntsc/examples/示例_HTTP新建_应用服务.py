# Import the ntsc module
import ntsc

# Create a new project object
project1 = ntsc.CreateProject()

# Connect to the server at IP address 192.168.15.100 and port 80
project1.Connect("192.168.15.97", 80)

# Log in to the server with username "admin" and password "admin"
project1.Login("admin", "admin")

# Create a new test case of type "HttpCps" with the name "Gateway"
case1 = project1.CreateCase("HttpCps", "Server")

# Configure the interfaces for the test case, using port1 and port2
case1.Config("Interface", "port1")

# Bind interfaces to CPU cores:
# - Bind port1 to CPU core 2
# - Bind port2 to CPU core 3
case1.Config("InterfaceCPU", "port1:2")
#
# Configure network subnet settings:
# - For port1: Subnet number 1, IP address range 18.1.2.2, netmask 16 bits, server IP range 18.1.1.2
case1.Config("NetworkSubnet", {"port1": {"SubnetNumber": 1, "IpAddrRange": "23.1.1.2", "Netmask": "16", "ServerIPRange":"23.1.1.100"}})
print(case1.case_config)

# Apply all configurations to the test case
case1.Apply(case1.case_config)

# Start the test case
case1.Start()

# Monitor the test execution
case1.Monitor()


