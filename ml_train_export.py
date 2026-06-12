import numpy as np
import onnx
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
from sklearn.ensemble import IsolationForest

# 1. بيانات تدريب وهمية (32 ميزة)
X_train = np.random.rand(10000, 32).astype(np.float32)

# 2. تدريب نموذج كشف شذوذ سريع وخفيف
model = IsolationForest(contamination=0.01, random_state=42)
model.fit(X_train)

# 3. التصدير إلى ONNX (مطابق تماماً لكود Rust)
initial_type = [('float_input', FloatTensorType([None, 32]))] # None = Dynamic Batch Size
onnx_model = convert_sklearn(model, initial_types=initial_type, target_opset=17)

# 4. الحفظ
with open("thor_anomaly_model.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())

print("✅ Model exported to thor_anomaly_model.onnx (Ready for Rust)")
