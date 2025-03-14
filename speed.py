import kivy
kivy.require('2.1.0')

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.image import Image
from kivy.uix.popup import Popup
from kivy.clock import Clock
import speedtest
import json
import time
import matplotlib.pyplot as plt
import numpy as np
from kivy.garden.matplotlib import FigureCanvasKivyAgg

# File to store speed history
DATA_FILE = "speed_history.json"

# Speed measurement function
def measure_speed():
    st = speedtest.Speedtest()
    st.get_best_server()
    download_speed = st.download() / 1e6  # Convert to Mbps
    upload_speed = st.upload() / 1e6  # Convert to Mbps
    return {"download": round(download_speed, 2), "upload": round(upload_speed, 2), "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}

# Function to save speed results
def save_results(data):
    try:
        with open(DATA_FILE, "r") as file:
            history = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        history = []

    history.append(data)

    with open(DATA_FILE, "w") as file:
        json.dump(history, file, indent=4)

# Function to provide tips
def get_tips(speed):
    if speed["download"] < 10:
        return "Your internet is slow! Try moving closer to the router or restarting it."
    elif speed["download"] < 50:
        return "Your internet speed is average. Consider upgrading your plan if needed."
    else:
        return "Your internet speed is great!"

# Function to plot history
def plot_speed_history():
    try:
        with open(DATA_FILE, "r") as file:
            history = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return None

    if not history:
        return None

    timestamps = [entry["timestamp"] for entry in history]
    download_speeds = [entry["download"] for entry in history]
    upload_speeds = [entry["upload"] for entry in history]

    plt.figure(figsize=(6, 3))
    plt.plot(timestamps, download_speeds, marker='o', label='Download (Mbps)', color='blue')
    plt.plot(timestamps, upload_speeds, marker='o', label='Upload (Mbps)', color='red')
    plt.xlabel("Time")
    plt.ylabel("Speed (Mbps)")
    plt.xticks(rotation=45)
    plt.legend()
    plt.title("Internet Speed History")
    plt.tight_layout()
    
    return plt

# Kivy UI
class SpeedTestApp(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', **kwargs)
        self.padding = 20
        self.spacing = 10

        # Title
        self.add_widget(Label(text="Internet Speed Test", font_size="24sp", bold=True))

        # Image
        self.add_widget(Image(source="network.png"))

        # Buttons
        self.test_button = Button(text="Start Test", font_size="18sp", size_hint=(None, None), size=(200, 50))
        self.test_button.bind(on_press=self.run_speed_test)
        self.add_widget(self.test_button)

        self.chart_button = Button(text="Show History", font_size="18sp", size_hint=(None, None), size=(200, 50))
        self.chart_button.bind(on_press=self.show_history)
        self.add_widget(self.chart_button)

        # Results Label
        self.result_label = Label(text="Speed Test Results Will Appear Here", font_size="16sp")
        self.add_widget(self.result_label)

    def run_speed_test(self, instance):
        self.result_label.text = "Testing..."
        Clock.schedule_once(self.perform_test, 1)

    def perform_test(self, dt):
        speed = measure_speed()
        save_results(speed)
        tips = get_tips(speed)
        self.result_label.text = f"Download: {speed['download']} Mbps\nUpload: {speed['upload']} Mbps\n\n{tips}"

    def show_history(self, instance):
        plt_data = plot_speed_history()
        if plt_data:
            popup = Popup(title="Speed History", content=FigureCanvasKivyAgg(plt_data.gca().figure), size_hint=(0.9, 0.7))
            popup.open()
        else:
            popup = Popup(title="Speed History", content=Label(text="No history available"), size_hint=(0.6, 0.4))
            popup.open()

class SpeedTestAppMain(App):
    def build(self):
        return SpeedTestApp()

if __name__ == "__main__":
    SpeedTestAppMain().run()