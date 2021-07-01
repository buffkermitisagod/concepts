import os
from pro import main as pro


banner = """
__          __  _   ____   _
\ \        / / |_| |  __| |_|
 \ \  /\  / /   _  | |__   _
  \ \/  \/ /   | | |  __| | |  
   \  /\  /    | | | |    | |
    \/  \/     |_| |_|    |_|
        [NO IPHONE WIFI]

"""
print(banner)
print("stage(1/4)")
print("[-]starting scan...")
print("[CTRL+C] press ctrl+c on the oppening window when done")

command = "xterm -geometry 100x50+0+0 -e 'python3 scan.py'"
os.system(command)

print("stage(2/4)")
print("[-] proccsesing...")
pro()

print("stage(3/4) and stage(4/4)")
print("[-] starting main attack...")

command = "xterm -geometry 100x50+0+0 -e 'python3 iphone_crash_wifi.py'" # and run the deuth script
os.system(command)