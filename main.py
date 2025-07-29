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
                fan_status TEXT DEFAULT 'OFF',
                heater_status TEXT DEFAULT 'OFF',
                soil_status TEXT DEFAULT 'OFF',
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sensor_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                temperature REAL,
                humidity REAL,
                water_level REAL,
                soil REAL
            );
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                mac TEXT PRIMARY KEY,
                toggle_fan BOOLEAN DEFAULT 0,
                toggle_heater BOOLEAN DEFAULT 0,
                toggle_soil BOOLEAN DEFAULT 0,
                min_temp INTEGER,
                max_temp INTEGER
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
    user_id = session.get('user_id')

    if not user_id:
        flash("Please log in", "warning")
        return redirect('/login')

    # Set session values from DB if they aren't already set
    if 'esp_mac' not in session or 'location' not in session:
        with get_db() as conn:
            cursor = conn.cursor()

            # Get first device MAC if not already set
            if 'esp_mac' not in session:
                cursor.execute("SELECT mac FROM devices WHERE user_id = ? ORDER BY id ASC LIMIT 1", (user_id,))
                row = cursor.fetchone()
                if row:
                    session['esp_mac'] = row['mac']
                    print("Auto-set MAC from DB:", row['mac'])

            # Get saved location if not already set
            if 'location' not in session:
                cursor.execute("SELECT location FROM users WHERE id = ?", (user_id,))
                row = cursor.fetchone()
                if row and row['location']:
                    session['location'] = row['location']
                    print("Auto-set location from DB:", row['location'])

    mac = session.get('esp_mac')
    location = session.get('location', 'Halifax')  # fallback to Halifax

    if not mac:
        flash("No device selected.", "warning")
        return render_template("home.html", data={"temp": "No device", "hum": "No device", "water": "No device", "soil": "No device"}, location=location)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM sensor_data
            WHERE mac = ?
            ORDER BY timestamp DESC
            LIMIT 1
        """, (mac,))
        row = cursor.fetchone()

    if row:
        data = {
            'temp': row['temperature'],
            'hum': row['humidity'],
            'water': row['water_level'],
            'soil': row['soil']
        }
    else:
        data = {"temp": "No data", "hum": "No data", "water": "No data", "soil": "No data"}

    try:
        return render_template("home.html", data=data, location=location)
    except Exception as e:
        print("Error rendering home.html:", e)
        return "Template rendering failed", 500

@app.route("/get_weather")
def get_weather():
    location = request.args.get("location")
    if not location:
        return jsonify({"error": "No location provided"}), 400

    # Step 1: Geocode
    geo_url = f"https://api.openweathermap.org/geo/1.0/direct"
    geo_res = requests.get(geo_url, params={
        "q": location,
        "limit": 1,
        "appid": openWeatherAPIKEY
    })
    geo_data = geo_res.json()
    if not geo_data:
        return jsonify({"error": "Invalid location"}), 404

    try:
        lat = geo_data[0]["lat"]
        lon = geo_data[0]["lon"]
    except (IndexError, KeyError):
        return jsonify({"error": "Invalid location or API response"}), 400

    # Step 2: Weather
    weather_url = "https://api.openweathermap.org/data/3.0/onecall"
    weather_res = requests.get(weather_url, params={
        "lat": lat,
        "lon": lon,
        "units": "metric",
        "appid": openWeatherAPIKEY
    })

    return jsonify(weather_res.json())


@app.route("/trends")
def trends():
    url = "https://api.thingspeak.com/channels/2996236/feeds.json"
    params = {
        "api_key": "UTVLHX407QEQ2HYN", #Thingspeak KEY(Testing/No need to hide)
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
    print("POST data:", request.form)

    user_id = session['user_id']
    user_ip = request.remote_addr
    if 'user_id' not in session:
        return redirect('/login')
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
                session['esp_mac'] = mac
                nickname = request.form.get('nickname', '')
                ip = request.remote_addr
                cursor.execute("INSERT INTO devices (user_id, mac, nickname, ip) VALUES (?, ?, ?, ?)",
                               (user_id, mac, nickname, ip))
        if 'location' in request.form:
            location = request.form['location']
            session['location'] = location
            cursor.execute("UPDATE users SET location = ? WHERE id = ?", (location, user_id))

        conn.commit()

    # Fetch current user info and devices
    cursor.execute("SELECT location FROM users WHERE id = ?", (user_id,))
    location = cursor.fetchone()['location']

    cursor.execute("SELECT * FROM devices WHERE user_id = ?", (user_id,))
    devices = cursor.fetchall()

    conn.close()
    return render_template('profile.html', location=location, devices=devices, device=device)

############################################################################ Device Registration

@app.route('/select-device', methods=['POST'])
def select_device():
    session['esp_ip'] = request.form.get('device_ip')
    session['esp_mac'] = request.form.get('device_mac')
    print("Selected device IP:", session['esp_ip'])
    print("Selected device MAC:", session['esp_mac'])
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
    cursor.execute("SELECT * FROM devices")
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
    ip = request.remote_addr
    session['esp_ip'] = ip
    return redirect('/')

############################################################################ Device Communication

@app.route('/set-command', methods=['POST'])
def set_command():
    mac = session.get('esp_mac')
    if not mac:
        return "No active device selected", 400

    cmd_type = request.form.get('cmd')
    temp_min = request.form.get('tempMin')
    temp_max = request.form.get('tempMax')

    with get_db() as conn:
        cursor = conn.cursor()

        # Initialize row in commands table if not exists
        cursor.execute("INSERT OR IGNORE INTO commands (mac) VALUES (?)", (mac,))

        if cmd_type == "toggle_fan":
            # Queue command
            cursor.execute("UPDATE commands SET toggle_fan = 1 WHERE mac = ?", (mac,))
            # Flip status
            cursor.execute("SELECT fan_status FROM devices WHERE mac = ?", (mac,))
            current = cursor.fetchone()[0]
            new_status = "OFF" if current == "ON" else "ON"
            cursor.execute("UPDATE devices SET fan_status = ? WHERE mac = ?", (new_status, mac,))

        elif cmd_type == "toggle_heater":
            cursor.execute("UPDATE commands SET toggle_heater = 1 WHERE mac = ?", (mac,))
            cursor.execute("SELECT heater_status FROM devices WHERE mac = ?", (mac,))
            current = cursor.fetchone()[0]
            new_status = "OFF" if current == "ON" else "ON"
            cursor.execute("UPDATE devices SET heater_status = ? WHERE mac = ?", (new_status, mac,))

        elif cmd_type == "toggle_soil":
            cursor.execute("UPDATE commands SET toggle_soil = 1 WHERE mac = ?", (mac,))
            cursor.execute("SELECT soil_status FROM devices WHERE mac = ?", (mac,))
            current = cursor.fetchone()[0]
            new_status = "OFF" if current == "ON" else "ON"
            cursor.execute("UPDATE devices SET soil_status = ? WHERE mac = ?", (new_status, mac,))

        elif cmd_type == "set_constraints":
            cursor.execute("UPDATE commands SET min_temp = ?, max_temp = ? WHERE mac = ?", (temp_min, temp_max, mac))

        conn.commit()

    return "Command queued", 200


@app.route('/data')
def get_data():
    mac = session.get('esp_mac')
    if not mac:
        return jsonify({"temp": "No device", "hum": "No device", "water": "No device", "soil": "No device"})

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sensor_data WHERE mac = ? ORDER BY timestamp DESC LIMIT 1", (mac,))
        sensor_row = cursor.fetchone()

        cursor.execute("SELECT fan_status, heater_status, soil_status FROM devices WHERE mac = ?", (mac,))
        status_row = cursor.fetchone()

    if sensor_row:
        return jsonify({
            "temp": sensor_row['temperature'],
            "hum": sensor_row['humidity'],
            "water": sensor_row['water_level'],
            "soil": sensor_row['soil'],
            "fan": status_row['fan_status'],
            "heater": status_row['heater_status'],
            "soilStatus": status_row['soil_status']
        })
    else:
        return jsonify({"temp": "No data", "hum": "No data", "water": "No data", "soil": "No data", "fan": "No data", "heater": "No data", "soilStatus": "No data"})


@app.route('/submit-data', methods=['POST'])
def submit_data():
    data = request.get_json()
    mac = data.get('mac')
    temp = data.get('temp')
    hum = data.get('hum')
    water = data.get('water')
    soil = data.get('soil')

    if not mac:
        return jsonify({'error': 'MAC address required'}), 400

    #get most recent data
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO sensor_data (mac, temperature, humidity, water_level, soil)
            VALUES (?, ?, ?, ?, ?)
        """, (mac, temp, hum, water, soil))
        conn.commit()

        #send back commands
        cursor.execute("SELECT * FROM commands WHERE mac = ?", (mac,))
        cmd_row = cursor.fetchone()

        if cmd_row:
            commands = {
                "toggle_fan": bool(cmd_row["toggle_fan"]),
                "toggle_heater": bool(cmd_row["toggle_heater"]),
                "toggle_soil": bool(cmd_row["toggle_soil"]),
                "update_constraints": {
                    "min_temp": cmd_row["min_temp"],
                    "max_temp": cmd_row["max_temp"]
                }
            }

            # Clear the commands after sending
            cursor.execute("""
                       UPDATE commands
                       SET toggle_fan = 0, toggle_heater = 0, toggle_soil = 0,
                           min_temp = NULL, max_temp = NULL
                       WHERE mac = ?
                   """, (mac,))

            conn.commit()
        else:
            commands = {}
    return jsonify(commands)



############################################################################ Main

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(host='0.0.0.0', port=5000)
