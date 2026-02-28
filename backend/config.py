import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'X-CloudSentinel-dev-secret')
    MODEL_PATH = os.environ.get('MODEL_PATH', 'models/X-CloudSentinel-distilbert')
    MAX_LENGTH = 512
    BATCH_SIZE = 16
    DEVICE = 'cuda' if os.environ.get('USE_GPU') == 'true' else 'cpu'
    
    # Classes for classification
    CLASSES = ['Secure', 'Misconfigured', 'SecretLeakage', 'HighRisk']
    
    # Weights for SQI calibration (will be updated)
    DEFAULT_WEIGHTS = {
        'sl': 0.35,  # Secret Leakage
        'mc': 0.25,  # Misconfiguration
        'ar': 0.25,  # Access Risk
        'ce': 0.15   # Configuration Entropy
    }

