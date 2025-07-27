from flask import Flask, g, jsonify, render_template, request,  redirect, session, url_for, flash
import requests
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'yoursecret'  # required for session
openWeatherAPIKEY = os.getenv('OPENWEATHER_API_KEY')
DATABASE = 'users.db'

############################################################################ DB
def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                location TEXT
            );
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                mac TEXT,
                nickname TEXT,
                ip TEXT,
                location TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
        ''')
        conn.commit()

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE, check_same_thread=False)
        db.row_factory = sqlite3.Row
    return db

############################################################################ Pages
@app.route('/')
def home():
    if 'user_id' not in session:
        flash("Please log in to continue.", "warning")
        return redirect('/login')
    esp_ip = session.get('esp_ip')
    location = session.get('location', 'Halifax')

    if not esp_ip:
        flash("No device selected. Please register and select a device.", "warning")
        return render_template("home.html", data=None, location=location)

    try:
        res = requests.get(f"{esp_ip}/data", timeout=5)
        data = res.json()
    except:
        data = {"temp": "-", "hum": "-", "water": "-", "soil": "-"}

    return render_template("home.html", data=data, location=location)

@app.route("/trends")
def trends():
    url = "https://api.thingspeak.com/channels/2996236/feeds.json"
    params = {
        "api_key": "UTVLHX407QEQ2HYN",
        "results": 8000
    }

    try:
        response = requests.get(url, params=params, timeout=5)
        response.raise_for_status()  # raises an exception for HTTP errors

        data = response.json()
        if isinstance(data, dict) and "feeds" in data:
            feeds = data["feeds"]
        else:
            print("Unexpected JSON format:", data)
            feeds = []

        timestamps = []
        temperatures = []
        humidities = []

        for feed in feeds:
            timestamps.append(feed["created_at"])
            temperatures.append(float(feed["field1"]) if feed["field1"] else None)
            humidities.append(float(feed["field2"]) if feed["field2"] else None)

        return render_template("trends.html",
                               timestamps=timestamps,
                               temperatures=temperatures,
                               humidities=humidities)

    except Exception as e:
        print("Error fetching ThingSpeak data:", e)
        return render_template("trends.html",
                               timestamps=[],
                               temperatures=[],
                               humidities=[])


@app.route("/info")
def info():
    return render_template("info.html")

############################################################################ User Registration

@app.route('/login', methods=['GET', 'POST'])
def login():
    with get_db() as conn:
        cursor = conn.cursor()

        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            action = request.form['action']  # 'login' or 'register'

            if action == 'register':
                # Register new user
                hashed_pw = generate_password_hash(password)
                try:
                    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
                    conn.commit()
                    flash("Registered successfully! You can now log in.", "success")
                except sqlite3.IntegrityError:
                    flash("Username already exists.", "danger")
            else:
                # Login user
                user = cursor.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
                if user and check_password_hash(user['password'], password):
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    flash("Logged in!", "success")
                    return redirect('/')
                else:
                    flash("Invalid credentials", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect('/')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect('/login')
    user_id = session['user_id']
    user_ip  = request.remote_addr
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
            UPDATE devices
            SET user_id = ?
            WHERE user_id IS NULL AND ip = ?
        """, (user_id, user_ip ))
    conn.commit()

    # Try to find a device at this IP
    cursor.execute("SELECT * FROM devices WHERE ip = ?", (user_ip,))
    device = cursor.fetchone()

    # Auto-link device if user logged in and device exists
    if device and device['user_id'] is None:
        cursor.execute("UPDATE devices SET user_id = ? WHERE mac = ?", (user_id, device['mac']))
        session['esp_ip'] = f"http://{device['ip']}"
        conn.commit()


    if request.method == 'POST':
        if 'mac' in request.form:
            mac = request.form['mac']
            cursor.execute("SELECT * FROM devices WHERE user_id = ? AND mac = ?", (user_id, mac))
            existing = cursor.fetchone()
            if existing:
                flash("Device with this MAC already registered.", "warning")
            else:
                nickname = request.form.get('nickname', '')
                cursor.execute("INSERT INTO devices (user_id, mac, nickname, ip) VALUES (?, ?, ?, NULL)",
                               (user_id, mac, nickname))
        if 'location' in request.form:
            location = request.form['location']
            session['location'] = location
            cursor.execute("UPDATE users SET location = ? WHERE id = ?", (location, user_id))

        conn.commit()

    # Fetch current user info and devices
    cursor.execute("SELECT location FROM users WHERE id = ?", (user_id,))
    location = cursor.fetchone()['location']

    cursor.execute("SELECT * FROM devices WHERE user_id = ? AND ip IS NOT NULL", (user_id,))
    devices = cursor.fetchall()

    conn.close()
    return render_template('profile.html', location=location, devices=devices, device=device)

############################################################################ Device Registration

@app.route('/register-device', methods=['POST'])
def register_device():
    data = request.get_json()
    mac = data.get('mac')
    ip = data.get('ip')
    user_id = session.get('user_id')  # optional for now
   # print(f"[DEBUG] /register-device sees mac: {mac}")
   # print(f"[DEBUG] /register-device sees User IP: {request.remote_addr}")

    if not mac or not ip:
        return jsonify({'error': 'Missing MAC or IP'}), 400

    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()

        # Save device if new
        cursor.execute("""
            INSERT OR IGNORE INTO devices (user_id, mac, nickname, ip)
            VALUES (?, ?, ?, ?)
        """, (user_id, mac, 'ESP Device', ip))

        # Update IP each time
        cursor.execute("""
            UPDATE devices SET ip = ? WHERE mac = ?
        """, (ip, mac))

        conn.commit()

    return jsonify({'status': 'registered'})


@app.route('/select-device', methods=['POST'])
def select_device():
    session['esp_ip'] = request.form.get('device_ip')
    flash("Active device set.", "info")
    return redirect('/profile')

@app.route('/remove-device', methods=['POST'])
def remove_device():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    mac_to_remove = request.form.get('mac')
    user_id = session['user_id']

    conn = get_db()
    cursor = conn.cursor()
   # print("MAC to remove:", mac_to_remove)
    cursor.execute("SELECT * FROM devices")
   # print(cursor.fetchall())
    cursor.execute("DELETE FROM devices WHERE user_id = ? AND mac = ?", (user_id, mac_to_remove))
    conn.commit()

    # Unset active device if it's the one being deleted
    if session.get('esp_mac') == mac_to_remove:
        session.pop('esp_mac', None)
        session.pop('esp_ip', None)

    return redirect(url_for('profile'))

@app.route('/check-device-ip')
def check_device_ip():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"has_ip": False})
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM devices WHERE user_id = ? AND ip IS NOT NULL", (user_id,))
    has_ip = cursor.fetchone()[0] > 0
    return jsonify({"has_ip": has_ip})


@app.route('/set-location', methods=['POST'])
def set_location():
    session['location'] = request.form['location']
    return redirect('/')

@app.route('/set-ip', methods=['POST'])
def set_ip():
    ip = request.form['esp_ip']
    session['esp_ip'] = ip
    return redirect('/')

############################################################################ Device Communication

@app.route('/toggleHeater')
def toggleHeater():
    try:
        esp_ip = session.get('esp_ip') # or 'http://192.168.2.236'
        res = requests.get(f"{esp_ip}/toggleHeater", timeout=5)
        return res.text
    except:
        return "ERROR", 503

@app.route('/toggleFan')
def toggleFan():
    try:
        esp_ip = session.get('esp_ip') # or 'http://192.168.2.236'
        res = requests.get(f"{esp_ip}/toggleFan", timeout=5)
        return res.text  # return "ON" or "OFF"
    except:
        return "ERROR", 503


@app.route('/toggleSoil')
def toggleSoil():
    try:
        esp_ip = session.get('esp_ip') # or 'http://192.168.2.236'
        res = requests.get(f"{esp_ip}/toggleSoil", timeout=5)
        return res.text
    except:
        return "ERROR", 503

@app.route("/data")
def get_data():
    esp_ip = session.get('esp_ip') # or 'http://192.168.2.236'
    if not esp_ip:
       # print(f"[DEBUG] Using ESP IP: {esp_ip}")
        return jsonify({"error": "ESP not registered"}),400
    try:
        res = requests.get(f"{esp_ip}/data", timeout=5)
        res.raise_for_status()
        data = res.json()
    except Exception as e:
       # print(f"ESP32 /data failed: {e}")
       # print(f"[DEBUG] Using ESP IP: {esp_ip}")
        data = {"temp": "?", "hum": "?", "water": "?", "soil": "?"}
        return jsonify(data), 503
    return jsonify(data)

@app.route('/set-constraints', methods=['POST'])
def set_constraints():
    temp_min = request.form['tempMin']
    temp_max = request.form['tempMax']
    try:
        esp_ip = session.get('esp_ip') # or 'http://192.168.2.236'
        requests.get(f"{esp_ip}/set-constraints?min={temp_min}&max={temp_max}", timeout=5)
    except:
        pass
    return redirect('/')

############################################################################ Main

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(host='0.0.0.0', port=5000)