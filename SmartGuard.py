import tkinter as tk
from tkinter import ttk, scrolledtext
import paho.mqtt.client as mqtt
import joblib
import json
import threading
import numpy as np
import pandas as pd
import requests
import tkinter as tk
from tkinter import ttk, scrolledtext
import paho.mqtt.client as mqtt
import joblib
import json
import threading
import numpy as np
import pandas as pd
import requests
import sqlite3
from datetime import datetime

# --- КОНФИГУРАЦИЯ ---
TELEGRAM_TOKEN = "ВАШ_ТОКЕН_ТУТ"
TELEGRAM_CHAT_ID = "ВАШ_АЙДИ_ТУТ"
MQTT_BROKER = "broker.emqx.io"
MQTT_TOPIC = "home/security/network/monitor"

class SmartHomeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IoT Security Monitor - Система защиты умного дома")
        self.root.geometry("800x650")
        self.root.configure(bg="#2c3e50")

        # 1. Инициализация Базы Данных
        self.db_conn = sqlite3.connect('alerts_history.db', check_same_thread=False)
        self.create_db()

        # 2. Загрузка ИИ-ядра
        try:
            self.model = joblib.load('anomaly_detector.pkl')
            self.scaler = joblib.load('scaler.pkl')
        except Exception as e:
            print(f"Ошибка загрузки моделей: {e}")

        self.setup_ui()
        self.start_mqtt()

    # --- МЕТОДЫ БАЗЫ ДАННЫХ ---
    def create_db(self):
        """Создание таблицы в БД, если она еще не существует"""
        cursor = self.db_conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS alerts 
                          (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                           time TEXT, 
                           bytes REAL, 
                           status TEXT)''')
        self.db_conn.commit()

    def save_to_db(self, timestamp, bytes_val, status):
        """Сохранение записи об инциденте в БД"""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("INSERT INTO alerts (time, bytes, status) VALUES (?, ?, ?)", 
                           (timestamp, bytes_val, status))
            self.db_conn.commit()
        except Exception as e:
            print(f"Ошибка записи в БД: {e}")

    # --- ИНТЕРФЕЙС ---
    def setup_ui(self):
        header = tk.Label(self.root, text="АРМ ОПЕРАТОРА МОНИТОРИНГА СЕТИ", 
                          font=("Arial", 16, "bold"), fg="white", bg="#2c3e50")
        header.pack(pady=20)

        # Индикатор статуса
        self.status_frame = tk.Frame(self.root, bg="#27ae60", height=100)
        self.status_frame.pack(fill="x", padx=20)
        
        self.status_label = tk.Label(self.status_frame, text="СИСТЕМА ЗАЩИЩЕНА", 
                                     font=("Arial", 18, "bold"), fg="white", bg="#27ae60")
        self.status_label.pack(pady=30)

        # Статистика
        self.stats_label = tk.Label(self.root, text="Событий обработано: 0 | Угроз выявлено: 0", 
                                    font=("Arial", 11), fg="white", bg="#2c3e50")
        self.stats_label.pack(pady=10)
        self.total_count = 0
        self.anomaly_count = 0

        # Лог событий
        tk.Label(self.root, text="Журнал регистрации инцидентов (в реальном времени):", 
                 fg="#bdc3c7", bg="#2c3e50").pack(anchor="w", padx=20)
        self.log_area = scrolledtext.ScrolledText(self.root, height=12, bg="#34495e", 
                                                  fg="#ecf0f1", font=("Consolas", 10))
        self.log_area.pack(fill="both", padx=20, pady=10)

        # Кнопка БД
        self.info_label = tk.Label(self.root, text="* Все данные автоматически сохраняются в alerts_history.db", 
                                   font=("Arial", 9, "italic"), fg="#7f8c8d", bg="#2c3e50")
        self.info_label.pack(pady=5)

    def log_message(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_area.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_area.see(tk.END)

    def update_ui_status(self, is_anomaly):
        if is_anomaly:
            self.status_frame.configure(bg="#e74c3c")
            self.status_label.configure(text="!!! ОБНАРУЖЕНА УГРОЗА !!!", bg="#e74c3c")
        else:
            self.status_frame.configure(bg="#27ae60")
            self.status_label.configure(text="СИСТЕМА ЗАЩИЩЕНА", bg="#27ae60")
        
        self.stats_label.configure(text=f"Событий обработано: {self.total_count} | Угроз выявлено: {self.anomaly_count}")

    def send_tg(self, payload):
        msg = f"⚠️ КРИТИЧЕСКАЯ АНОМАЛИЯ!\nОбнаружен подозрительный трафик.\nДанные: {payload}"
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        try: requests.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": msg}, timeout=2)
        except: pass

    # --- ЛОГИКА ОБРАБОТКИ ---
    def on_message(self, client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode())
            
            # Подготовка данных для ИИ
            cols = ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]
            features_df = pd.DataFrame([[
                payload.get('duration', 0), payload.get('orig_bytes', 0), 
                payload.get('resp_bytes', 0), payload.get('orig_pkts', 0), 
                payload.get('resp_pkts', 0)
            ]], columns=cols)
            
            # Предсказание модели
            features_scaled = self.scaler.transform(features_df)
            prediction = self.model.predict(features_scaled)
            is_anomaly = True if prediction[0] == 1 else False
            
            # Подготовка данных для сохранения
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            bytes_val = payload.get('orig_bytes', 0)
            status_text = "УГРОЗА" if is_anomaly else "Безопасно"

            # 3. СОХРАНЕНИЕ В БАЗУ ДАННЫХ
            self.save_to_db(timestamp, bytes_val, status_text)

            self.total_count += 1
            if is_anomaly:
                self.anomaly_count += 1
                self.log_message(f"КРИТИЧЕСКОЕ: Аномалия обнаружена! ({bytes_val} байт)")
                self.send_tg(payload)
            else:
                self.log_message(f"OK: Пакет проверен. ({bytes_val} байт)")

            # Обновление UI
            self.root.after(0, self.update_ui_status, is_anomaly)

        except Exception as e:
            print(f"Ошибка анализа: {e}")

    def start_mqtt(self):
        def mqtt_thread():
            client = mqtt.Client()
            client.on_message = self.on_message
            client.connect(MQTT_BROKER, 1883, 60)
            client.subscribe(MQTT_TOPIC)
            client.loop_forever()
        
        threading.Thread(target=mqtt_thread, daemon=True).start()
        self.log_message("Сетевой модуль мониторинга запущен...")

if __name__ == "__main__":
    root = tk.Tk()
    app = SmartHomeApp(root)
    root.mainloop()
from datetime import datetime

# --- КОНФИГУРАЦИЯ ---
TELEGRAM_TOKEN = "8855367839:AAHNDr5FUi-NeAVEF2xvDp4GOAHwNwL6Lcg"
TELEGRAM_CHAT_ID = "2061889672"
MQTT_BROKER = "broker.emqx.io"
MQTT_TOPIC = "home/security/network/monitor"

class SmartHomeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IoT Security Monitor - Система защиты умного дома")
        self.root.geometry("800x600")
        self.root.configure(bg="#2c3e50")

        # Загрузка ИИ
        self.model = joblib.load('anomaly_detector.pkl')
        self.scaler = joblib.load('scaler.pkl')

        self.setup_ui()
        self.start_mqtt()

    def setup_ui(self):
        # Заголовок
        header = tk.Label(self.root, text="МОНИТОРИНГ СЕТЕВОЙ АКТИВНОСТИ", font=("Arial", 18, "bold"), fg="white", bg="#2c3e50")
        header.pack(pady=20)

        # Индикатор статуса
        self.status_frame = tk.Frame(self.root, bg="#27ae60", height=100)
        self.status_frame.pack(fill="x", padx=20)
        
        self.status_label = tk.Label(self.status_frame, text="СИСТЕМА ЗАЩИЩЕНА", font=("Arial", 20, "bold"), fg="white", bg="#27ae60")
        self.status_label.pack(pady=30)

        # Статистика
        self.stats_label = tk.Label(self.root, text="Обработано пакетов: 0 | Атак выявлено: 0", font=("Arial", 12), fg="white", bg="#2c3e50")
        self.stats_label.pack(pady=10)
        self.total_count = 0
        self.anomaly_count = 0

        # Лог событий
        tk.Label(self.root, text="Журнал событий:", fg="white", bg="#2c3e50").pack(anchor="w", padx=20)
        self.log_area = scrolledtext.ScrolledText(self.root, height=15, bg="#34495e", fg="#ecf0f1", font=("Consolas", 10))
        self.log_area.pack(fill="both", padx=20, pady=10)

    def log_message(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_area.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_area.see(tk.END)

    def update_status(self, is_anomaly):
        if is_anomaly:
            self.status_frame.configure(bg="#e74c3c")
            self.status_label.configure(text="!!! ОБНАРУЖЕНА УГРОЗА !!!", bg="#e74c3c")
        else:
            self.status_frame.configure(bg="#27ae60")
            self.status_label.configure(text="СИСТЕМА ЗАЩИЩЕНА", bg="#27ae60")
        
        self.stats_label.configure(text=f"Обработано пакетов: {self.total_count} | Атак выявлено: {self.anomaly_count}")

    def send_tg(self, payload):
        msg = f"⚠️ ВНИМАНИЕ: Сетевая аномалия!\nДанные: {payload}"
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        try: requests.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": msg}, timeout=2)
        except: pass

    def on_message(self, client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode())
            
            # Подготовка для ИИ
            cols = ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]
            features_df = pd.DataFrame([[
                payload.get('duration', 0), payload.get('orig_bytes', 0), 
                payload.get('resp_bytes', 0), payload.get('orig_pkts', 0), 
                payload.get('resp_pkts', 0)
            ]], columns=cols)
            
            features_scaled = self.scaler.transform(features_df)
            prediction = self.model.predict(features_scaled)
            
            is_anomaly = True if prediction[0] == 1 else False
            self.total_count += 1
            
            if is_anomaly:
                self.anomaly_count += 1
                self.log_message(f"КРИТИЧЕСКОЕ: Аномалия обнаружена! ({payload['orig_bytes']} байт)")
                self.send_tg(payload)
            else:
                self.log_message(f"OK: Пакет проверен. ({payload['orig_bytes']} байт)")

            # Обновляем UI в главном потоке
            self.root.after(0, self.update_status, is_anomaly)

        except Exception as e:
            print(f"Ошибка анализа: {e}")

    def start_mqtt(self):
        def mqtt_thread():
            client = mqtt.Client()
            client.on_message = self.on_message
            client.connect(MQTT_BROKER, 1883, 60)
            client.subscribe(MQTT_TOPIC)
            client.loop_forever()
        
        threading.Thread(target=mqtt_thread, daemon=True).start()
        self.log_message("Сетевой модуль MQTT запущен. Ожидание данных...")

if __name__ == "__main__":
    root = tk.Tk()
    app = SmartHomeApp(root)
    root.mainloop()