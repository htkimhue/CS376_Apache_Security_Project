import re
import pandas as pd
from sklearn.ensemble import IsolationForest

# 1. Đường dẫn file log Apache
log_file_path = "/var/log/apache2/access.log"

# Biểu thức chính quy parse định dạng Combined Log
log_pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[\w:/]+\s[+\-]\d{4})\] "(?P<method>\S+) (?P<url>\S+)\s* \S*" (?P<status>\d{3}) (?P<bytes>\S+)'
)

logs = []
try:
    with open(log_file_path, "r") as f:
        for line in f:
            match = log_pattern.match(line)
            if match:
                logs.append(match.groupdict())
except FileNotFoundError:
    print(f"[!] Không tìm thấy file log tại: {log_file_path}")
    exit(1)

# 2. Chuyển đổi thành DataFrame
df = pd.DataFrame(logs)

if df.empty:
    print("[!] Dữ liệu log trống.")
    exit(0)

df["status"] = df["status"].astype(int)

# 3. Trích xuất đặc trưng (Feature Engineering) theo từng IP
features = df.groupby("ip").agg(
    total_requests=("status", "count"),
    error_requests=("status", lambda x: (x >= 400).sum())
).reset_index()

# 4. Huấn luyện mô hình Anomaly Detection (Isolation Forest)
model = IsolationForest(contamination=0.2, random_state=42)
features["anomaly_score"] = model.fit_predict(features[["total_requests", "error_requests"]])

# 5. Hiển thị kết quả
print("=== KET QUA PHAN TICH NHAT KY TRUY CAP (ACCESS LOG) ===")
print(features)

# 6. Cảnh báo các IP bị đánh dấu bất thường (anomaly_score == -1)
anomalies = features[features["anomaly_score"] == -1]
if not anomalies.empty:
    print("\n[!] CANH BAO AN NINH: phat hien IP co dau hieu tan cong bat thuong:")
    print(anomalies[["ip", "total_requests", "error_requests"]])
else:
    print("\n[+] Khong phat hien IP bat thuong.")