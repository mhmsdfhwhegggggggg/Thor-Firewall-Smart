# Thor UEBA ML Models

Place your ONNX model files here.

## Expected file
```
models/thor_ueba_model.onnx
```

## Training your model

Use the provided training script:

```bash
pip install scikit-learn skl2onnx numpy
python scripts/train_and_export.py
```

This generates `models/thor_ueba_model.onnx` using IsolationForest trained on synthetic normal-behavior network traffic.

## Model specs

| Property | Value |
|----------|-------|
| Algorithm | IsolationForest |
| Features | 32 dimensions |
| Input shape | (1, 32) float32 |
| Output | [label, anomaly_score] |
| Inference time | < 1ms CPU |
| Model size | ~500KB |

## Feature dimensions (32 total)

| Index | Feature | Range |
|-------|---------|-------|
| 0 | Event type (0=net, 1=proc, 2=xdp) | 0-2 |
| 1 | Destination port normalized | 0-1 |
| 2 | Protocol (TCP=0.5, UDP=0.85) | 0-1 |
| 3 | Direction (0=in, 1=out) | 0-1 |
| 4 | Is RFC1918 destination | 0-1 |
| 5 | UID normalized | 0-1 |
| 6 | PID normalized | 0-1 |
| 7 | Hour of day | 0-1 |
| 8-11 | Destination IP octets | 0-1 each |
| 12-15 | Process name encoding | 0-1 each |
| 16-31 | Flow statistics (reserved) | 0-1 each |

## Production notes

- Run `thor-agent` with `--model models/thor_ueba_model.onnx`
- If no model file is found, the agent runs in **rule-only mode** (still fully functional)
- Retrain monthly with new baseline data for drift resistance
