import ntsc

project1 = ntsc.CreateProject()
# Connect to the NTSC server
project1.Connect("192.168.18.147", 80)
# Login
project1.Login("admin", "admin")
# Download history tester log
project1.DownloadHistoryTesterLog("HttpCps_TP_admin_20250425-14:46:20")