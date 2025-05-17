# Import the ntsc module, which presumably contains functions and classes for project management and testing.
import ntsc
# Import the json module to handle JSON data.
import json

# Create a new project instance using the CreateProject method from the ntsc module.
project = ntsc.CreateProject()

# Connect to the specified IP address and port.
project.Connect("192.168.20.199", 80)

# Log in to the system with the provided username and password.
project.Login("admin", "admin")

# Read JSON data from the specified ZIP file. Note: 'ReadJsonByZip' might cause unresolved reference issues.
config = project.ReadJsonByZip("./20250509_22_55_31.zip")
# Parse the JSON data into a Python dictionary.
config_dict = json.loads(config)
# Extract the test type from the configuration dictionary.
test_type = config_dict.get("TestType")
# Extract the DUT (Device Under Test) role from the configuration dictionary.
dut_role = config_dict.get("DUTRole")

# Create a new test case with the extracted test type and DUT role.
case = project.CreateCase(test_type, dut_role)

# Replace the default values of the test case with the configuration from the dictionary.
case.ReplaceDefaultValue(config_dict)
# Configure the test name of the test case.
case.Config("TestName","test_name")
# Configure the port limit values for the test case.
case.Config("PortLimitValue", "port1:9999", "port2:9889","port5:9779","port6:8888")
# Apply the configuration settings to the test case.
case.Apply(case.case_config)

# Start the test case.
case.Start()

# Monitor the test case during its execution.
case.Monitor()

# Retrieve the test results.
case.Getresult()

# Generate a report based on the test results.
case.GenerateReport()

# Get a summary of the test results.
case.GetSummary()

# Download the test report in HTML format.
case.DownLoadReport("html")