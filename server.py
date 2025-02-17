from flask import Flask, request, jsonify, send_file, redirect, url_for, render_template
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit
import os
import uuid
from datetime import datetime, timedelta
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.secret_key = "STRONG_SECRET_KEY"  # Replace with a strong secret key
socketio = SocketIO(app, cors_allowed_origins="*")

DISCONNECT_THRESHOLD = timedelta(seconds=10)  # Time after which a device is considered disconnected

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Command and response storage
devices = {}   # {device_id: {"name": "Device Name", "status": "connected", "last_active": datetime}}
commands = {}  # {device_id: {"command": ..., "data": ...}}
responses = {} # {device_id: {"message": ..., "image_path": ..., "file_path": ...}}

UPLOAD_FOLDER = "uploaded_files"
IMAGE_FOLDER = "images"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(IMAGE_FOLDER, exist_ok=True)

# User storage (replace with a database in production)
users = {
    "username": generate_password_hash("passowrd"),
}

class User(UserMixin):
    def __init__(self, id):
        self.id = id

# Ensure this is in your server.py
@socketio.on('send_image')
def handle_image(data):
    """Broadcast received images to all connected clients."""
    emit('update_image', data, broadcast=True)

def remove_inactive_devices():
    """Remove devices that have been inactive for too long."""
    now = datetime.now()
    inactive_devices = [
        device_id for device_id, info in devices.items()
        if now - info.get("last_active", now) > DISCONNECT_THRESHOLD
    ]
    for device_id in inactive_devices:
        print(f"Removing inactive device: {device_id} ({devices[device_id]['name']})")
        del devices[device_id]
        del commands[device_id]
        del responses[device_id]

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username in users and check_password_hash(users[username], password):
            user = User(username)
            login_user(user)
            return redirect(url_for("index"))
        return "Invalid username or password", 401
    return '''
    <form method="POST">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
        <button type="submit">Login</button>
    </form>
    '''

@app.route("/styles.css")
def send_css():
    return send_file("styles.css")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    # Instead of returning the HTML string, we render our template:
    return render_template("index.html")

@app.route("/register_device", methods=["POST"])
def register_device():
    """Register (or re-register) a device."""
    try:
        data = request.json
        if not data or "device_name" not in data:
            return jsonify({"error": "Missing 'device_name' in request body"}), 400

        device_name = data["device_name"]
        requested_id = data.get("device_id")

        if requested_id:
            # If the client has a device_id, reuse it
            device_id = requested_id
        else:
            # Otherwise, generate a new one
            device_id = str(uuid.uuid4())

        devices[device_id] = {
            "name": device_name,
            "status": "connected",
            "last_active": datetime.now()
        }
        commands[device_id] = {"command": None, "data": None}
        responses[device_id] = {"message": "", "image_path": None, "file_path": None}

        return jsonify({"device_id": device_id})

    except Exception as e:
        print(f"Error in /register_device: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/devices", methods=["GET"])
@login_required
def list_devices():
    """List all active devices."""
    remove_inactive_devices()
    return jsonify({"devices": devices})

@app.route("/heartbeat/<device_id>", methods=["POST"])
def heartbeat(device_id):
    """Update the last active timestamp for a device."""
    if device_id not in devices:
        return jsonify({"error": "Device not found"}), 404
    devices[device_id]["last_active"] = datetime.now()
    return jsonify({"success": True})

@app.route("/send_command", methods=["POST"])
@login_required
def send_command():
    """Send a command to a specific device."""
    data = request.get_json()
    device_id = data.get("device_id")
    command = data.get("command")
    command_data = data.get("data", "")

    if device_id not in commands:
        return jsonify({"error": "Device not found"}), 404

    # Set the new command
    commands[device_id] = {"command": command, "data": command_data}
    # Clear the old response
    responses[device_id] = {"message": "", "image_path": None, "file_path": None}
    return jsonify({"success": True})

@app.route("/get_command/<device_id>", methods=["GET"])
def get_command(device_id):
    """Fetch the command for a specific device."""
    try:
        if device_id not in commands:
            return jsonify({"error": "Device not found"}), 404
        return jsonify(commands[device_id])
    except Exception as e:
        print(f"Error in /get_command: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/clear_command/<device_id>", methods=["POST"])
def clear_command(device_id):
    """Clear the command for a specific device."""
    if device_id not in commands:
        return jsonify({"error": "Device not found"}), 404
    commands[device_id] = {"command": None, "data": None}
    return jsonify({"success": True})

@app.route("/status", methods=["GET"])
def get_status():
    """Return the status of all devices."""
    if not devices:
        return jsonify({"status": "No devices connected."})

    status_dict = {
        device_id: (
            f"Awaiting execution of command '{cmd['command']}' with data: {cmd['data']}"
            if cmd['command'] else "No command to execute."
        )
        for device_id, cmd in commands.items()
    }
    return jsonify({"status": status_dict})

@app.route("/response/<device_id>", methods=["GET"])
def get_response(device_id):
    """Get the latest response for a specific device."""
    if device_id not in responses:
        return jsonify({"error": "Device not found"}), 404
    return jsonify(responses[device_id])

@app.route("/upload_image/<device_id>", methods=["POST"])
def upload_image(device_id):
    """Upload an image file from a specific device."""
    if device_id not in responses:
        return jsonify({"error": "Device not found"}), 404
    image_file = request.files.get('image')
    if image_file:
        filename = f"{device_id}_{image_file.filename}"
        image_path = os.path.join(IMAGE_FOLDER, filename)
        image_file.save(image_path)
        responses[device_id]["image_path"] = f"/images/{filename}"
    return jsonify({"success": True})

@app.route("/upload_file/<device_id>", methods=["POST"])
def upload_file(device_id):
    """Upload a file from a specific device."""
    if device_id not in responses:
        return jsonify({"error": "Device not found"}), 404
    file_obj = request.files.get('file')
    if file_obj:
        filename = f"{device_id}_{file_obj.filename}"
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file_obj.save(file_path)
        responses[device_id]["file_path"] = f"/uploaded_files/{filename}"
    return jsonify({"success": True})

@app.route('/uploaded_files/<filename>')
def get_uploaded_file(filename):
    """Serve a previously uploaded file to the user."""
    return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True)

@app.route('/images/<filename>')
def get_image(filename):
    """Serve a previously uploaded image to the user."""
    return send_file(os.path.join(IMAGE_FOLDER, filename))

@app.route("/upload_message/<device_id>", methods=["POST"])
def upload_message(device_id):
    """Upload a text response from a specific device."""
    if device_id not in responses:
        return jsonify({"error": "Device not found"}), 404
    message = request.json.get("message", "")
    responses[device_id]["message"] = message
    return jsonify({"success": True})

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)  # Change to socketio.run
