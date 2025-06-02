from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
import time
import base64
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///my_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())

    def __repr__(self):
        return f'<Message {self.id}: {self.content}>'

with app.app_context():
    db.create_all()
    print("Database created or already exists.")

def requires_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Basic '):
            return jsonify({"error": "Authentication required"}), 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}
        try:
            encoded_credentials = auth_header.split(' ')[1]
            decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
            username, password_provided = decoded_credentials.split(':', 1)
        except Exception:
            return jsonify({"error": "Invalid authentication credentials"}), 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password_provided):
            return jsonify({"error": "Invalid username or password"}), 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}

        g.current_user = user
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def home():
    return "<h1>This is the third task!</h1>"

@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "Missing username or password"}), 400

    username = data['username']
    password = data['password']

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 409

    try:
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User registered successfully", "user_id": new_user.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to register user", "details": str(e)}), 500

@app.route('/process_json', methods=['POST'])
@requires_auth
def process_json_data():
    start_time = time.time()
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    message_content = data.get('message', 'No message provided')

    try:
        new_message = Message(content=message_content)
        db.session.add(new_message)
        db.session.commit()

        end_time = time.time()
        processing_time_ms = (end_time - start_time) * 1000

        response_data = {
            "status": "success",
            "received_data": data,
            "saved_message_id": new_message.id,
            "processed_by_user": g.current_user.username,
            "processing_time_ms": round(processing_time_ms, 2)
        }
        return jsonify(response_data), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to save data", "details": str(e)}), 500

@app.route('/messages', methods=['GET'])
def get_messages():
    messages = Message.query.all()
    messages_list = []
    for msg in messages:
        messages_list.append({
            "id": msg.id,
            "content": msg.content,
            "timestamp": msg.timestamp.isoformat()
        })
    return jsonify(messages_list), 200

if __name__ == '__main__':
    app.run(debug=True)