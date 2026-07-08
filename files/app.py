# /opt/flask-wazuh-uploader

from flask import Flask, request, jsonify, render_template_string
import os

app = Flask(__name__)

# Path to the folder that Wazuh will monitor via ossec.conf
UPLOAD_FOLDER = '/var/wazuh_monitor'

# Create the upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

HTML_FORM = '''
<!doctype html>
<html>
<head><title>Upload to Wazuh Monitor</title></head>
<body>
    <h1>Upload File for Wazuh Monitoring</h1>
    <form method="post" enctype="multipart/form-data" action="/upload">
        <input type="file" name="file">
        <input type="submit" value="Upload File">
    </form>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_FORM)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Basic security: prevent path traversal
    filename = os.path.basename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    try:
        file.save(filepath)
        return jsonify({
            'success': True,
            'message': f'File {filename} uploaded successfully. Wazuh should detect it now.',
            'path': filepath
        })
    except Exception as e:
        return jsonify({'error': f'Error saving file: {str(e)}'}), 500

if __name__ == '__main__':
    print(f"Flask server is running...")
    print(f"Files will be saved to: {UPLOAD_FOLDER}")
    print("Make sure Wazuh is monitoring this folder.")
    app.run(host='0.0.0.0', port=5000, debug=True)
