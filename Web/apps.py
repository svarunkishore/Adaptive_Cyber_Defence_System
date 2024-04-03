from flask import Flask, render_template, request, flash, redirect, url_for
from werkzeug.utils import secure_filename
import os
import tensorflow as tf
import pandas as pd
import numpy as np
from androguard.core.bytecodes.apk import APK
import shap

app = Flask(__name__)
app.secret_key = "fun"

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'apk', 'txt'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_permissions(apk_path):
    try:
        a = APK(apk_path)
        permissions = a.get_permissions()
        permissions = [permission.replace("android.permission.", "") for permission in permissions]
        return permissions
    except Exception as e:
        print(f"Error: {e}")
        return None

def create_csv_and_predict_malware(apk_path, features, trained_model):
    extracted_permissions = extract_permissions(apk_path)

    if extracted_permissions:
        feature_values = {feature: 0 for feature in features}

        for permission in extracted_permissions:
            if permission in features:
                feature_values[permission] = 1

        app_features_array = np.array([list(feature_values.values())])

        predicted_probabilities = trained_model.predict(app_features_array)

        if predicted_probabilities[0] > 0.5:
            explanation = f"This application is predicted to be malware with a probability of {predicted_probabilities[0][0]}."
            return explanation, 'Malware', feature_values
        else:
            explanation = f"This application is predicted to be benign with a probability of {1 - predicted_probabilities[0][0]}."
            return explanation, 'Benign', feature_values
    else:
        return "Failed to extract permissions.", None, None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/detect', methods=['GET', 'POST'])
def detect():
    if request.method == 'POST':
        if 'apk_file' not in request.files or 'features_file' not in request.files:
            flash('Please upload both APK and features files')
            return redirect(request.url)
        apk_file = request.files['apk_file']
        features_file = request.files['features_file']
        if apk_file.filename == '' or features_file.filename == '':
            flash('Please upload both APK and features files')
            return redirect(request.url)
        if apk_file and allowed_file(apk_file.filename) and features_file and allowed_file(features_file.filename):
            apk_filename = secure_filename(apk_file.filename)
            features_filename = secure_filename(features_file.filename)
            apk_path = os.path.join(app.config['UPLOAD_FOLDER'], apk_filename)
            features_path = os.path.join(app.config['UPLOAD_FOLDER'], features_filename)
            apk_file.save(apk_path)
            features_file.save(features_path)
            trained_model = tf.keras.models.load_model('trained_model.h5')
            with open(features_path, 'r') as f:
                features = f.read().splitlines()
            result, category, app_features = create_csv_and_predict_malware(apk_path, features, trained_model)
            return render_template('result.html', result=result, category=category, app_features=app_features)
    return render_template('detect.html')

if __name__ == "__main__":
    app.run(debug=True)
