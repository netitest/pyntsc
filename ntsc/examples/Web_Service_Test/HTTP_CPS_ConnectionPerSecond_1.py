# Import the ntsc module, which likely provides functionality for network testing and server configuration.
import ntsc

# Create a new project instance using the ntsc module.
project1 = ntsc.CreateProject()

# Establish a connection to the target server with the specified IP address and port.
project1.Connect("192.168.20.199", 80)

# Log in to the server using the provided username and password.
project1.Login("admin", "admin")

# Create a new test case of type "HttpCps" with the role "Server".
case1 = project1.CreateCase("HttpCps", "Server")

# Configure the network interfaces to be used in the test case.
case1.Config("Interface", "port1, port2,port5,port6")

# Configure the CPU cores assigned to each network interface.
case1.Config("InterfaceCPU", "port1:12,13,14,15")
case1.Config("InterfaceCPU", "port2:16,17,18,19")
case1.Config("InterfaceCPU", "port5:2,3,4,5")
case1.Config("InterfaceCPU", "port6:6,7,8,9")

# Configure the network subnet settings for each interface.
case1.Config("NetworkSubnet", {"port1": {"SubnetNumber": 1, "IpAddrRange": "10.10.10.20", "Netmask": "16", "ServerIPRange":"10.10.10.11"}})
case1.Config("NetworkSubnet", {"port2": {"SubnetNumber": 1, "IpAddrRange": "10.10.20.20", "Netmask": "16", "ServerIPRange":"10.10.20.11"}})
case1.Config("NetworkSubnet", {"port5": {"SubnetNumber": 1, "IpAddrRange": "10.10.30.20", "Netmask": "16", "ServerIPRange":"10.10.30.11"}})
case1.Config("NetworkSubnet", {"port6": {"SubnetNumber": 1, "IpAddrRange": "10.10.40.20", "Netmask": "16", "ServerIPRange":"10.10.40.11"}})

# Configure the test case object with monitoring, variate, web test project name, and file object.
case1.Config("CaseObject", {"Monitor": "Default monitoring object Ping", "Variate": "None", "WebTestProjectName": "test", "FileObject": "test"})

# Configure the port limit values for each interface.
case1.Config("PortLimitValue", "port1:9999", "port2:9889","port5:9779","port6:8888")

# Configure the test duration in seconds.
case1.Config("TestDuration", 300)

# Apply the configured settings to the test case.
case1.Apply(case1.case_config)

# Start the test case execution.
case1.Start()

# Monitor the test case while it is running.
case1.Monitor()

# Retrieve the test results.
case1.Getresult()

# Generate a report based on the test results.
case1.GenerateReport()

# Get a summary of the test results.
case1.GetSummary()

# Download the test report in HTML format.
case1.DownLoadReport("html")