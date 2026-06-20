import paho.mqtt.client as mqtt
import pandas as pd
import json
import time

MQTT_BROKER = "broker.emqx.io"
MQTT_TOPIC = "home/security/network/monitor"

# Загружаем данные для отправки
try:
    df = pd.read_csv('final_home_iot_dataset_v4.csv')
    # Берем 5 атак и 5 нормальных строк
    test_data = pd.concat([
        df[df['anomaly_score'] == 0].head(5),
        df[df['anomaly_score'] == 1].head(5)
    ]).sample(frac=1) # Перемешать
except:
    print("Ошибка: Не найден файл датасета!")
    exit()

# Совместимость версий
try:
    from paho.mqtt.enums import CallbackAPIVersion
    client = mqtt.Client(CallbackAPIVersion.VERSION1)
except:
    client = mqtt.Client()

client.connect(MQTT_BROKER, 1883, 60)

print(f"Начинаю отправку {len(test_data)} пакетов в топик {MQTT_TOPIC}...")

for _, row in test_data.iterrows():
    payload = {
        "duration": row['duration'],
        "orig_bytes": row['orig_bytes'],
        "resp_bytes": row['resp_bytes'],
        "orig_pkts": row['orig_pkts'],
        "resp_pkts": row['resp_pkts']
    }
    client.publish(MQTT_TOPIC, json.dumps(payload))
    print(f"Отправлено: {payload['orig_bytes']} байт. Аномалия в датасете: {row['anomaly_score']}")
    time.sleep(3)

print("Симуляция завершена.")