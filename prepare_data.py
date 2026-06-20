import pandas as pd
import os

# Возвращаем порты (3, 5) и поведенческие признаки (8, 9, 10, 16, 18)
SELECTED_INDICES = [3, 5, 8, 9, 10, 16, 18]
COLUMN_NAMES = ["id.orig_p", "id.resp_p", "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]

def load_and_clean(file_path, force_label):
    if not os.path.exists(file_path): return None
    try:
        df = pd.read_csv(file_path, sep='\t', comment='#', header=None, low_memory=False)
        df = df[SELECTED_INDICES]
        df.columns = COLUMN_NAMES
        df.replace('-', '0', inplace=True)
        for col in COLUMN_NAMES:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        df['anomaly_score'] = force_label
        return df
    except: return None

# Загружаем все 6 папок (3 нормы, 3 атаки)
files_to_load = [
    ('data_normal_1/conn.log.labeled.txt', 0),
    ('data_normal_2/conn.log.labeled.txt', 0),
    ('data_normal_3/conn.log.labeled.txt', 0),
    ('data_malware_1/conn.log.labeled.txt', 1),
    ('data_malware_2/conn.log.labeled.txt', 1),
    ('data_malware_3/conn.log.labeled.txt', 1)
]

all_data = []
for path, label in files_to_load:
    df_part = load_and_clean(path, label)
    if df_part is not None: all_data.append(df_part)

final_df = pd.concat(all_data, ignore_index=True)
final_df.to_csv('final_home_iot_dataset_v4.csv', index=False)
print(f"Датасет v4 (сбалансированный) готов. Строк: {len(final_df)}")