
# Import the ntsc module
import ntsc

# Create a new project object
project = ntsc.CreateProject()

# Connect to the server at IP address 192.168.15.100 and port 80
project.Connect("192.168.15.100", 80)

# Log in to the server with username "admin" and password "admin"
project.Login("admin", "admin")

# Create a new test case of type "Ipv4FragAttack" with the name "Gateway"
case = project.CreateCase("Ipv4FragAttack", "Gateway")

# Configure the interfaces for the test case, using port1 and port2
case.Config("Interface", "port1", "port2")

# Bind interfaces to CPU cores:
# - Bind port1 to CPU core 2
# - Bind port2 to CPU core 3
case.Config("InterfaceCPU", "port1:2", "port2:3")

# Configure network subnet settings:
# - For port1: Subnet number 1, IP address range 18.1.2.2, netmask 16 bits, server IP range 18.1.1.2
case.Config("NetworkSubnet", {"port1": {"SubnetNumber": 1, "IpAddrRange": "18.1.2.2", "Netmask": "16", "ServerIPRange": "18.1.1.2"}})

# - For port2: Subnet number 1, IP address range 18.1.1.2, netmask 16 bits
case.Config("NetworkSubnet", {"port2": {"SubnetNumber": 1, "IpAddrRange": "18.1.1.2", "Netmask": "16"}})

# Apply all configurations to the test case
case.Apply(case.case_config)

# Start the test case
case.Start()

# Monitor the test execution
case.Monitor()

# Retrieve and get the test results layer2
case.Getresult()
