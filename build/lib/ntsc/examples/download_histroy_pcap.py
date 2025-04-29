# Import the ntsc module
import ntsc

# Create a new project object
project = ntsc.CreateProject()

# Connect to the NTSC server at IP address 192.168.18.147 and port 80
project.Connect("192.168.18.147", 80)

# Log in to the NTSC server with username "admin" and password "admin"
project.Login("admin", "admin")

# Download the packet capture (PCAP) file for the specified test case history
project.DownloadHistoryPcap("HttpCps_TP_admin_test1")

