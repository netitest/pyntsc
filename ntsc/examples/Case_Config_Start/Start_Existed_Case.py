
# Import the ntsc module
import ntsc

# Create a new project object
project = ntsc.CreateProject()

# Connect to the server at IP address 192.168.15.100 and port 80
project.Connect("192.168.15.100", 80)

# Log in to the server with username "admin" and password "admin"
project.Login("admin", "admin")

# Create a new test case of type "HttpCps" with the name "Gateway"
case = project.CreateCase("HttpCps", "Gateway")

case.Apply(case.case_config)

# Start the test case
# case.Start()

# Start the test case by name
case.StartExistExample("20250507-11_37_23")

# Monitor the test execution
case.Monitor()

# Retrieve and get the test results layer2
case.Getresult()
