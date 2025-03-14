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
import os

# Use regular matplotlib without kivy.garden integration
# We'll generate images and display them instead
import matplotlib
matplotlib.use('Agg')  # Use Agg backend which doesn't require a display
import matplotlib.pyplot as plt
from kivy.core.image import Image as CoreImage
from io import BytesIO

# File to store speed history
DATA_FILE = "speed_history.json"

# Speed measurement function
def measure_speed():
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        download_speed = st.download() / 1e6  # Convert to Mbps
        upload_speed = st.upload() / 1e6  # Convert to Mbps
        return {"download": round(download_speed, 2), "upload": round(upload_speed, 2), "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
    except Exception as e:
        print(f"Error measuring speed: {e}")
        return {"download": 0, "upload": 0, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}

# Function to save speed results
def save_results(data):
    try:
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, "r") as file:
                history = json.load(file)
        else:
            history = []

        history.append(data)

        with open(DATA_FILE, "w") as file:
            json.dump(history, file, indent=4)
    except Exception as e:
        print(f"Error saving results: {e}")

# Function to provide tips
def get_tips(speed):
    if speed["download"] < 10:
        return "Your internet is slow! Try moving closer to the router or restarting it."
    elif speed["download"] < 50:
        return "Your internet speed is average. Consider upgrading your plan if needed."
    else:
        return "Your internet speed is great!"

# Function to generate a plot and return it as a Kivy image
def generate_plot_image():
    try:
        if not os.path.exists(DATA_FILE):
            return None
            
        with open(DATA_FILE, "r") as file:
            history = json.load(file)

        if not history:
            return None

        # Limit to last 10 entries to avoid overcrowding
        if len(history) > 10:
            history = history[-10:]

        timestamps = [entry["timestamp"].split()[1] for entry in history]  # Just show time for readability
        download_speeds = [entry["download"] for entry in history]
        upload_speeds = [entry["upload"] for entry in history]

        plt.figure(figsize=(8, 4), dpi=100)
        plt.plot(range(len(timestamps)), download_speeds, marker='o', label='Download (Mbps)', color='blue')
        plt.plot(range(len(timestamps)), upload_speeds, marker='o', label='Upload (Mbps)', color='red')
        plt.xlabel("Time")
        plt.ylabel("Speed (Mbps)")
        plt.xticks(range(len(timestamps)), timestamps, rotation=45)
        plt.legend()
        plt.title("Internet Speed History")
        plt.tight_layout()
        
        # Save plot to a BytesIO object
        buf = BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        
        # Create a Kivy Image from the BytesIO buffer
        img = CoreImage(buf, ext='png')
        plt.close()  # Close the figure to free memory
        
        return img
    except Exception as e:
        print(f"Error generating plot: {e}")
        return None

# Kivy UI
class SpeedTestApp(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', **kwargs)
        self.padding = 20
        self.spacing = 10

        # Title
        self.add_widget(Label(text="Internet Speed Test", font_size="24sp", bold=True, size_hint=(1, 0.1)))

        # Image container
        self.image_container = BoxLayout(size_hint=(1, 0.3))
        try:
            self.image_container.add_widget(Image(source="network.png"))
        except:
            # Fallback if image doesn't exist
            self.image_container.add_widget(Label(text="[Image Placeholder]"))
        self.add_widget(self.image_container)

        # Button Layout
        button_layout = BoxLayout(orientation='horizontal', size_hint=(1, 0.2), spacing=10)
        
        self.test_button = Button(text="Start Test", font_size="18sp")
        self.test_button.bind(on_press=self.run_speed_test)
        button_layout.add_widget(self.test_button)

        self.chart_button = Button(text="Show History", font_size="18sp")
        self.chart_button.bind(on_press=self.show_history)
        button_layout.add_widget(self.chart_button)
        
        self.add_widget(button_layout)

        # Results Label
        self.result_label = Label(
            text="Speed Test Results Will Appear Here", 
            font_size="16sp",
            size_hint=(1, 0.4),
            halign='center',
            valign='middle'
        )
        self.result_label.bind(size=self.result_label.setter('text_size'))
        self.add_widget(self.result_label)

    def run_speed_test(self, instance):
        self.test_button.disabled = True
        self.result_label.text = "Testing... Please wait, this may take a moment."
        Clock.schedule_once(self.perform_test, 0.1)

    def perform_test(self, dt):
        try:
            speed = measure_speed()
            save_results(speed)
            tips = get_tips(speed)
            self.result_label.text = f"Download: {speed['download']} Mbps\nUpload: {speed['upload']} Mbps\n\n{tips}"
        except Exception as e:
            self.result_label.text = f"Error during test: {str(e)}\nPlease try again."
        finally:
            self.test_button.disabled = False

    def show_history(self, instance):
        img = generate_plot_image()
        if img:
            # Create an Image widget with the plot
            plot_image = Image(texture=img.texture, size_hint=(1, 0.9))
            
            # Create content layout for popup
            content = BoxLayout(orientation='vertical')
            content.add_widget(plot_image)
            
            # Add close button
            close_button = Button(text="Close", size_hint=(1, 0.1))
            content.add_widget(close_button)
            
            # Create and open popup
            popup = Popup(title="Speed History", content=content, size_hint=(0.9, 0.8))
            close_button.bind(on_press=popup.dismiss)
            popup.open()
        else:
            # Show a message if no history is available
            popup = Popup(
                title="Speed History", 
                content=Label(text="No history available yet. Run some tests first!"), 
                size_hint=(0.6, 0.4)
            )
            popup.open()

class SpeedTestAppMain(App):
    def build(self):
        self.title = "Internet Speed Test"
        return SpeedTestApp()

if __name__ == "__main__":
    SpeedTestAppMain().run()