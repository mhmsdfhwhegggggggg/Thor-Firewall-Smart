""" 
Thor UEBA/GNN Training & ONNX Export Pipeline 
============================================== 
Trains a robust anomaly detection model and exports it strictly 
for compatibility with Rust's `ort` crate. 
""" 
import torch 
import torch.nn as nn 
import numpy as np 
import onnx 
from pathlib import Path 
from sklearn.model_selection import train_test_split 
import logging 

# تأكد من تثبيت: pip install torch onnx skl2onnx scikit-learn numpy 
from common.datasets import load_all_datasets 
from common.features import FEATURE_DIMENSION 

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s') 
logger = logging.getLogger(__name__) 

class ThorUEBANet(nn.Module): 
    """ 
    Robust Autoencoder for Anomaly Detection. 
    Architecture optimized for fast inference and stability. 
    """ 
    def __init__(self, input_dim=FEATURE_DIMENSION, latent_dim=8): 
        super().__init__() 
        self.encoder = nn.Sequential( 
            nn.Linear(input_dim, 64), 
            nn.LayerNorm(64), 
            nn.ReLU(), 
            nn.Dropout(0.1), 
            nn.Linear(64, 32), 
            nn.LayerNorm(32), 
            nn.ReLU(), 
            nn.Linear(32, latent_dim), 
            nn.Tanh() # Bound latent space for stability 
        ) 
        self.decoder = nn.Sequential( 
            nn.Linear(latent_dim, 32), 
            nn.LayerNorm(32), 
            nn.ReLU(), 
            nn.Linear(32, 64), 
            nn.LayerNorm(64), 
            nn.ReLU(), 
            nn.Linear(64, input_dim), 
            nn.Sigmoid() # Output matches normalized input [0, 1] 
        ) 

    def forward(self, x): 
        latent = self.encoder(x) 
        reconstructed = self.decoder(latent) 
        return reconstructed 

    def anomaly_score(self, x): 
        """Calculate reconstruction error (MSE per sample)""" 
        recon = self.forward(x) 
        error = torch.mean((x - recon) ** 2, dim=1) 
        # Normalize error to 0-1 range using sigmoid for consistent thresholding 
        return torch.sigmoid(error * 10.0 - 2.0) 

def main(): 
    logger.info(" Loading datasets...") 
    # X shape: (N, 32), y shape: (N,) -> 0=benign, 1=malicious 
    X, y = load_all_datasets() 

    # Split data: Train ONLY on benign (normal) data for unsupervised learning 
    X_benign = X[y == 0] 
    X_malicious = X[y == 1] 

    X_train, X_val = train_test_split(X_benign, test_size=0.2, random_state=42) 

    logger.info(f" Loaded: {len(X_train)} train (benign), {len(X_val)} val (benign), {len(X_malicious)} malicious")

    # Initialize model 
    model = ThorUEBANet(input_dim=FEATURE_DIMENSION, latent_dim=8) 
    criterion = nn.MSELoss() 
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.001, weight_decay=1e-5) 

    # Convert to tensors 
    train_tensor = torch.tensor(X_train, dtype=torch.float32) 
    val_tensor = torch.tensor(X_val, dtype=torch.float32) 

    BATCH_SIZE = 256 
    EPOCHS = 50 

    logger.info(" Starting training...") 
    best_val_loss = float('inf') 

    for epoch in range(EPOCHS): 
        model.train() 
        # Simple batch training loop 
        perm = torch.randperm(train_tensor.size(0)) 
        epoch_loss = 0.0 

        for i in range(0, train_tensor.size(0), BATCH_SIZE): 
            batch_idx = perm[i:i+BATCH_SIZE] 
            batch = train_tensor[batch_idx] 

            optimizer.zero_grad() 
            output = model(batch) 
            loss = criterion(output, batch) 
            loss.backward() 
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0) 
            optimizer.step() 

            epoch_loss += loss.item() 

        # Validation 
        model.eval() 
        with torch.no_grad(): 
            val_output = model(val_tensor) 
            val_loss = criterion(val_output, val_tensor).item() 

        if val_loss < best_val_loss: 
            best_val_loss = val_loss 
            torch.save(model.state_dict(), 'models/best_ueba_model.pth') 

        if epoch % 10 == 0: 
            logger.info(f"Epoch {epoch}: Train Loss = {epoch_loss/len(train_tensor):.6f}, Val Loss = {val_loss:.6f}") 

    # Load best model for export 
    model.load_state_dict(torch.load('models/best_ueba_model.pth')) 
    model.eval() 

    # ========================================== 
    # CRITICAL: ONNX EXPORT FOR RUST COMPATIBILITY 
    # ========================================== 
    logger.info(" Exporting to ONNX for Rust (ort crate)...") 

    # 1. Dummy input MUST be float32 and match exact feature dimension 
    dummy_input = torch.randn(1, FEATURE_DIMENSION, dtype=torch.float32) 

    export_path = Path("models/thor_ueba.onnx") 
    export_path.parent.mkdir(exist_ok=True) 

    torch.onnx.export( 
        model, 
        dummy_input, 
        str(export_path), 
        export_params=True, 
        opset_version=17, # Required for modern ort crate 
        do_constant_folding=True, 
        input_names=['float_input'], # MUST match Rust code expectation 
        output_names=['anomaly_score'], 
        dynamic_axes={ 
            'float_input': {0: 'batch_size'}, 
            'anomaly_score': {0: 'batch_size'} 
        } 
    ) 

    # 2. Verify the exported model 
    import onnxruntime as ort 
    session = ort.InferenceSession(str(export_path)) 
    input_name = session.get_inputs()[0].name 

    # Test inference 
    test_data = np.random.randn(1, FEATURE_DIMENSION).astype(np.float32) 
    result = session.run(None, {input_name: test_data}) 

    logger.info(f" ONNX Export Successful!") 
    logger.info(f" Path: {export_path}") 
    logger.info(f" Input Name: {input_name} (Type: {session.get_inputs()[0].type})") 
    logger.info(f" Output Shape: {result[0].shape}") 
    logger.info(f" Test Score: {result[0][0][0]:.4f}") 

if __name__ == '__main__': 
    main()
