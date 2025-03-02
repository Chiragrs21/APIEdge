from flask import Flask, request

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def handle_request():
    if request.method == 'POST':
        payload = request.get_data(as_text=True)
        print(f"Received Payload: {payload}")
        return f"Payload received: {payload}", 200
    return "Send a POST request with payload data."


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
