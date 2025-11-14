
# Import the ntsc module
import ntsc

# Create a new project object
project = ntsc.CreateProject()

# Connect to the server at IP address 192.168.15.100 and port 80
project.Connect("192.168.18.222", 80)

# Log in to the server with username "admin" and password "admin"
project.Login("admin", "admin")

# Create a new test case of type "Ipv4FragAttack" with the name "Gateway"
case = project.CreateCase("Ipv4FragAttack", "Gateway")

port1, port2 = case.use_ports("port1","port2")
port1.set_port_core_bind("2")
port2.set_port_core_bind("3")

port1.configure_network({"IpAddrRange": "17.1.2.2+100","Netmask": "16","ServerIPRange":"17.1.1.2+10"})
port2.configure_network({"IpAddrRange": "17.1.1.2+10", "Netmask": "16"})

# Apply all configurations to the test case
case.Apply(case.case_config)

# Start the test case
case.Start()

# Monitor the test execution
case.Monitor()

# Retrieve and get the test results layer2
case.Getresult()
