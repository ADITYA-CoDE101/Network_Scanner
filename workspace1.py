import os 
from datetime import datetime

'''def worksp_name(name):
    os.mkdir(/workspaces/Network_Scanner/workspace)

worksp_name("adi")'''
class Requirments:
    def __init__(self):
        self.dirName = str(input("Create a workspacew - "))

    def workspace(self):
        try:
            os.mkdir(f"/workspaces/Network_Scanner/workspace/{self.dirName}")
        except FileExistsError:
            print("Workspace already exist!")

    def log(self, work_sp, location, data:list):
        locations = f"/workspaces/Network_Scanner/workspace/{work_sp}/{location}"
        with open(locations , "a") as f:
            f.write(f"[{datetime.now()}] {data[0]} {data[1]}\n")
            


