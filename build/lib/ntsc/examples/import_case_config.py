import ntsc_v8 as ntsc
# Step 1: Create a task
# Step 2: Check whether it is possible to connect to the server.
# Step 3: Perform user login to obtain access rights to the interface.
# Step 4: Invoke the import use case method
project1 = ntsc.CreateProject()
project1.Connect("192.168.15.100", 80)
session = project1.Login("admin", "admin")
project1.import_case("HttpCps_TP_admin_20250424-16_25_55.zip", "HttpCps")