from flask import Flask, request, jsonify
import time

app = Flask(__name__)

@app.route('/')
def home():
    return "<h1>Hello, Flask!</h1>"

@app.route('/process_json', methods=['POST'])
def process_json_data():
    start_time = time.time()

    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()

    end_time = time.time()
    processing_time_ms = (end_time - start_time) * 1000 #милисекунды

    #JSON ответ
    response_data = {
        "status": "success",
        "received_data": data,
        "processing_time_ms": round(processing_time_ms, 2)
    }

    #JSON ответ и http200 (ok)
    return jsonify(response_data), 200

if __name__ == '__main__':
    app.run(debug=True)
