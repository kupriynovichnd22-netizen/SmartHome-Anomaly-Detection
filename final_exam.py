import pandas as pd
import joblib
from sklearn.metrics import classification_report, confusion_matrix

# 1. Загрузка обученных ресурсов
print("Загрузка модели и скалера...")
model = joblib.load('anomaly_detector.pkl')
scaler = joblib.load('scaler.pkl')

# 2. Загрузка ВСЕГО исходного датасета
print("Чтение основного датасета (184 413 строк)...")
df = pd.read_csv('final_home_iot_dataset_v4.csv')

# 3. Подготовка данных
# Убираем порты, как мы и договаривались в "честной" модели
X_full = df.drop(columns=['anomaly_score', 'id.orig_p', 'id.resp_p'])
y_full = df['anomaly_score']

# 4. МАСШТАБИРОВАНИЕ
print("Масштабирование данных...")
X_full_scaled = scaler.transform(X_full)

# 5. ПРЕДСКАЗАНИЕ (Экзамен)
print("Запуск глобальной проверки... Это может занять около минуты.")
y_pred_full = model.predict(X_full_scaled)

# 6. ВЫВОД РЕЗУЛЬТАТОВ
print("\n" + "="*40)
print("РЕЗУЛЬТАТЫ ГЛОБАЛЬНОГО ТЕСТИРОВАНИЯ (184 413 записей)")
print("="*40)

print("\nОтчет по классификации:")
print(classification_report(y_full, y_pred_full, target_names=['Норма', 'УГРОЗА']))

print("\nМатрица ошибок (на всем массиве данных):")
print(confusion_matrix(y_full, y_pred_full))

# Рассчитаем точность
correct = (y_full == y_pred_full).sum()
total = len(y_full)
print(f"\nИтоговая точность системы: {correct/total*100:.2f}%")
print(f"Всего выявлено атак: {((y_pred_full == 1) & (y_full == 1)).sum()} из {y_full.sum()}")
print("="*40)