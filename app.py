from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
import firebase_admin
from firebase_admin import credentials, firestore
import qrcode
import io
import base64
from flask_cors import CORS
import hashlib
from datetime import datetime
import os
import logging
import secrets
import razorpay

# Initialize Flask app
app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Firebase
def init_firebase():
    if all(key in os.environ for key in ['FIREBASE_TYPE', 'FIREBASE_PROJECT_ID']):
        return credentials.Certificate({
            "type": os.environ["FIREBASE_TYPE"],
            "project_id": os.environ["FIREBASE_PROJECT_ID"],
            "private_key": os.environ["FIREBASE_PRIVATE_KEY"].replace('\\n', '\n'),
            "client_email": os.environ["FIREBASE_CLIENT_EMAIL"],
            "token_uri": os.environ["FIREBASE_TOKEN_URI"]
        })
    elif os.path.exists("firebase-creds.json"):
        return credentials.Certificate("firebase-creds.json")
    raise ValueError("Missing Firebase config")

try:
    cred = init_firebase()
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    logger.info("Firebase initialized successfully")
except Exception as e:
    logger.error(f"Firebase init error: {str(e)}")
    db = None

# Initialize Razorpay
razorpay_client = razorpay.Client(auth=(
    os.environ.get('RAZORPAY_KEY_ID', 'rzp_test_YOUR_KEY_ID'),
    os.environ.get('RAZORPAY_KEY_SECRET', 'YOUR_KEY_SECRET')
))

# Helper Functions
def hash_password(password):
    return hashlib.sha256((password + os.environ.get('PEPPER', 'default_pepper')).encode()).hexdigest()

def validate_session():
    if 'username' not in session:
        return False
    if db is None:
        return False
    user_ref = db.collection('users').document(session['username']).get()
    return user_ref.exists

def validate_order_data(data):
    if not isinstance(data, dict):
        return False, "Invalid data format"
    
    required_fields = ['roll_number', 'phone_number', 'food_items']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return False, f"Missing required fields: {', '.join(missing_fields)}"
    
    if not isinstance(data['food_items'], list) or len(data['food_items']) == 0:
        return False, "food_items must be a non-empty list"
    
    for item in data['food_items']:
        if not isinstance(item, dict):
            return False, "Each food item must be an object"
        if 'name' not in item or 'price' not in item or 'quantity' not in item:
            return False, "Each food item must have name, price and quantity"
        try:
            float(item['price'])
            int(item['quantity'])
        except (ValueError, TypeError):
            return False, "Price must be a number and quantity must be an integer"
    
    return True, ""

# Routes
@app.route("/")
def home():
    return redirect(url_for('login'))

@app.route("/login", methods=['GET', 'POST'])
def login():
    if validate_session():
        return redirect(url_for('home_page'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Username and password are required', 'danger')
            return redirect(url_for('login'))
        
        try:
            user_ref = db.collection('users').document(username).get()
            if user_ref.exists and user_ref.to_dict().get('password') == hash_password(password):
                session['username'] = username
                return redirect(url_for('home_page'))
            flash('Invalid username or password', 'danger')
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('Login error', 'danger')
    
    return render_template('login.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if validate_session():
        return redirect(url_for('home_page'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        if not username or not password:
            flash('Username and password are required', 'danger')
            return redirect(url_for('register'))
        
        if len(username) < 4:
            flash('Username must be at least 4 characters', 'danger')
            return redirect(url_for('register'))
        
        if len(password) < 8:
            flash('Password must be at least 8 characters', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        try:
            if db.collection('users').document(username).get().exists:
                flash('Username already exists', 'danger')
                return redirect(url_for('register'))
            
            db.collection('users').document(username).set({
                'username': username,
                'password': hash_password(password),
                'created_at': datetime.now(),
                'last_login': None,
                'role': 'user'
            })
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            flash('Registration failed. Please try again.', 'danger')
    
    return render_template('register.html')

@app.route("/logout")
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route("/home")
def home_page():
    if not validate_session():
        return redirect(url_for('login'))
    
    try:
        username = session['username']
        orders_ref = db.collection('orders').where('username', '==', username)
        orders = [doc.to_dict() for doc in orders_ref.stream()]
        
        return render_template('home.html', 
                            username=username,
                            orders=orders[-5:],
                            razorpay_key_id=os.environ.get('RAZORPAY_KEY_ID', 'rzp_test_YOUR_KEY_ID'))
    except Exception as e:
        logger.error(f"Error loading home: {str(e)}")
        flash('Error loading dashboard', 'danger')
        return redirect(url_for('login'))

@app.route("/index")
def index():
    if not validate_session():
        return redirect(url_for('login'))
    return render_template('index.html', 
                          username=session['username'],
                          razorpay_key_id=os.environ.get('RAZORPAY_KEY_ID', 'rzp_test_YOUR_KEY_ID'))

@app.route("/order_history")
def order_history():
    if not validate_session():
        return redirect(url_for('login'))
    
    try:
        username = session['username']
        orders_ref = db.collection('orders').where('username', '==', username)
        orders = [doc.to_dict() for doc in orders_ref.stream()]
        
        return render_template('order_history.html',
                            username=username,
                            orders=orders)
    except Exception as e:
        logger.error(f"Error fetching order history: {str(e)}")
        flash('Error fetching order history', 'danger')
        return redirect(url_for('home_page'))

@app.route("/api/orders", methods=["POST"])
def create_order():
    if not validate_session():
        return jsonify({"error": "Unauthorized"}), 401
    
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    try:
        data = request.get_json()
        if data is None:
            return jsonify({"error": "Invalid or empty JSON"}), 400
        
        is_valid, validation_msg = validate_order_data(data)
        if not is_valid:
            return jsonify({"error": validation_msg}), 400

        total = sum(item['price'] * item['quantity'] for item in data['food_items'])
        username = session['username']

        # Generate a random 8-character alphanumeric ID
        order_id = secrets.token_urlsafe(6)[:8]
        
        # Generate QR code with the 8-digit ID
        qr = qrcode.make(order_id)
        img_io = io.BytesIO()
        qr.save(img_io, 'PNG')
        qr_base64 = base64.b64encode(img_io.getvalue()).decode()
        
        order_data = {
            "id": order_id,
            "food_items": data['food_items'],
            "phone_number": data['phone_number'],
            "roll_number": data['roll_number'],
            "status": "confirmed",
            "created_at": datetime.now(),
            "username": username,
            "amount": round(total, 2),
            "qr_code": qr_base64
        }
        
        # Save to Firestore with the custom 8-char ID
        db.collection('orders').document(order_id).set(order_data)
        
        # Also save to user's bookings subcollection
        db.collection('users').document(username).collection('bookings').document(order_id).set(order_data)
        
        return jsonify({
            "status": "success",
            "order_id": order_id,
            "qr_code": qr_base64,
            "amount": total
        }), 201

    except Exception as e:
        logger.error(f"Order creation failed: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/create_razorpay_order", methods=["POST"])
def create_razorpay_order():
    if not validate_session():
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        data = request.get_json()
        order_id = data.get('order_id')
        amount = data.get('amount')
        
        razorpay_order = razorpay_client.order.create({
            'amount': int(amount * 100),  # Convert to paise
            'currency': 'INR',
            'receipt': order_id,
            'payment_capture': 1
        })
        
        return jsonify({
            "id": razorpay_order["id"],
            "amount": razorpay_order["amount"],
            "currency": razorpay_order["currency"]
        })
        
    except Exception as e:
        logger.error(f"Razorpay error: {str(e)}")
        return jsonify({"error": "Payment processing failed"}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
