import ntsc
# Step 1: Create a task
# Step 2: Check whether it is possible to connect to the server.
# Step 3: Perform user login to obtain access rights to the interface.
# Step 4: Invoke the export use case method
project1 = ntsc.CreateProject()
project1.Connect("192.168.15.100", 80)
session = project1.Login("admin", "admin")
project1.export_case("20250506-10_08_22")