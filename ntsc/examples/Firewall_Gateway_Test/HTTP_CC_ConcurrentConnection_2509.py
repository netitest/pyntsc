import ntsc

# Create a new project instance using the ntsc module.
project1 = ntsc.CreateProject()

# Establish a connection to the target server with the specified IP address and port.
project1.Connect("192.168.18.222", 80)
# Log in to the server using the provided username and password.
project1.Login("admin", "admin")

case1 = project1.CreateCase("HttpCc", "Gateway")
port1, port2 = case1.use_ports("port1","port2")
port1.set_port_core_bind("2")
port2.set_port_core_bind("3")

port1.configure_network({"IpAddrRange": "17.1.2.2+100","Netmask": "16","ServerIPRange":"17.1.1.2+10"})
port2.configure_network({"IpAddrRange": "17.1.1.2+10", "Netmask": "16"})

# port1.configure_network({"IpAddrRange": "3ffe:0:17:1::2:2+100","Netmask": "64","SubnetNumber":"2","SubnetEnable":"yes","ServerIPRange":'3ffe:0:17:1::1:2+10'})
# port2.configure_network({"IpAddrRange": "3ffe:0:17:1::1:2+10", "Netmask": "64","SubnetNumber":"2","SubnetEnable":"yes"})

case1.Apply(case1.case_config)

# Start the test case execution.
case1.Start()

# Monitor the test case while it is running.
case1.Monitor()

# Retrieve the test results.
case1.Getresult()
