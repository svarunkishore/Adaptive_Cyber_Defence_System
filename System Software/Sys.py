import os
import win32api
from kivy.app import App
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.filechooser import FileChooserListView
from kivy.utils import platform
import csv
import pandas as pd
import numpy as np
import tensorflow as tf
from androguard.core.bytecodes.apk import APK
from kivy.animation import Animation
from kivy.graphics import Color, Rectangle

class CustomFileChooserListView(FileChooserListView):
    def is_hidden(self, fn):
        if platform == 'win':
            try:
                attributes = win32api.GetFileAttributes(fn)
                return attributes & 2
            except:
                return False
        return super(CustomFileChooserListView, self).is_hidden(fn)

class MalwareDetectorLayout(GridLayout):

    def __init__(self, **kwargs):
        super(MalwareDetectorLayout, self).__init__(**kwargs)
        self.cols = 2
        self.spacing = [10, 10]

        # Set background color for the layout
        with self.canvas.before:
            Color(0.1, 0.1, 0.1, 1)  # Dark gray background
            self.rect = Rectangle(size=self.size, pos=self.pos)

        # Bind the rectangle's size and position to the layout's size and position
        self.bind(size=self._update_rect, pos=self._update_rect)

        # Create labels and text inputs for APK file and features file selection
        self.add_widget(Label(text='APK File:', color=(0.9, 0.9, 0.9, 1)))  # Light gray text
        self.apk_file = CustomFileChooserListView()
        self.apk_file.path = os.getcwd()  # Set default path to current directory
        self.add_widget(self.apk_file)

        self.add_widget(Label(text='Features File:', color=(0.9, 0.9, 0.9, 1)))  # Light gray text
        self.features_file = CustomFileChooserListView()
        self.features_file.path = os.getcwd()  # Set default path to current directory
        self.find_features_file()  # Automatically find features file
        self.add_widget(self.features_file)

        # Create a button to detect malware with smooth animation
        self.detect_button = Button(text='Detect Malware', background_color=(0.2, 0.8, 0.4, 1))  # Light green button
        self.detect_button.bind(on_press=self.detect_malware)
        self.add_widget(self.detect_button)

    def _update_rect(self, instance, value):
        self.rect.pos = instance.pos
        self.rect.size = instance.size

    def find_features_file(self):
        current_directory = os.getcwd()
        files = os.listdir(current_directory)
        for file in files:
            if file.lower() == 'features.txt':
                self.features_file.selection = [os.path.join(current_directory, file)]
                break

    def detect_malware(self, instance):
        apk_path = self.apk_file.selection[0] if self.apk_file.selection else None
        features_path = self.features_file.selection[0] if self.features_file.selection else None

        if not apk_path or not os.path.isfile(apk_path):
            self.show_popup("Error", "Please select a valid APK file.")
            return

        if not features_path or not os.path.isfile(features_path):
            self.show_popup("Error", "Features file 'features.txt' not found.")
            return

        # Perform malware detection
        output_csv_path = 'output.csv'

        try:
            extracted_permissions = self.extract_permissions(apk_path)
            if extracted_permissions:
                features = self.read_features(features_path)
                self.create_csv_and_predict_malware(apk_path, features, output_csv_path)
            else:
                self.show_popup("Extraction Error", "Failed to extract permissions.")
        except Exception as e:
            self.show_popup("Error", str(e))

    def extract_permissions(self, apk_path):
        try:
            a = APK(apk_path)
            permissions = a.get_permissions()
            permissions = [permission.replace("android.permission.", "") for permission in permissions]
            return permissions
        except Exception as e:
            raise e

    def read_features(self, features_path):
        with open(features_path, 'r') as f:
            features = f.read().splitlines()
        return features

    def create_csv_and_predict_malware(self, apk_path, features, output_csv_path):
        extracted_permissions = self.extract_permissions(apk_path)

        if extracted_permissions:
            feature_values = {feature: 0 for feature in features}
            for permission in extracted_permissions:
                if permission in features:
                    feature_values[permission] = 1

            with open(output_csv_path, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=features)
                writer.writeheader()
                writer.writerow(feature_values)
        else:
            self.show_popup("Extraction Error", "Failed to extract permissions.")
            return

        # Load the TensorFlow Lite model
        interpreter = tf.lite.Interpreter(model_path="model.tflite")
        interpreter.allocate_tensors()

        # Prepare input data
        app_features_array = np.array([list(feature_values.values())], dtype=np.float32)
        input_details = interpreter.get_input_details()
        output_details = interpreter.get_output_details()

        # Perform inference
        interpreter.set_tensor(input_details[0]['index'], app_features_array)
        interpreter.invoke()
        predicted_probabilities = interpreter.get_tensor(output_details[0]['index'])

        if predicted_probabilities[0][0] > 0.5:
            explanation = "This application is predicted to be malware with a probability of {:.2f}% based on the following features:".format(predicted_probabilities[0][0] * 100)
            malware_features = [feature for feature, value in feature_values.items() if value == 1]
            malware_features_list = "\n- " + "\n- ".join(malware_features)
            explanation += malware_features_list
            self.show_popup("Prediction Result", explanation)
        else:
            explanation = "This application is predicted to be benign with a probability of {:.2f}%.".format((1 - predicted_probabilities[0][0]) * 100)
            self.show_popup("Prediction Result", explanation)

    def show_popup(self, title, message):
        popup = Popup(title=title, content=Label(text=message), size_hint=(None, None), size=(800, 400))
        popup.open()

class MalwareDetectorApp(App):
    def build(self):
        return MalwareDetectorLayout()

if __name__ == '__main__':
    MalwareDetectorApp().run()
