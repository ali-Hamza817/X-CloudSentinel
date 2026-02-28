import shap
import torch
import numpy as np

class SentinelExplainer:
    def __init__(self, classifier):
        self.classifier = classifier
        self.model = classifier.model
        self.tokenizer = classifier.tokenizer
        self.device = classifier.device
        
        # SHAP text explainer wrap
        def predictor(texts):
            # SHAP might pass numpy array, tokenizer needs list of strings
            texts_list = [str(t) for t in texts]
            inputs = self.tokenizer(texts_list, return_tensors="pt", padding=True, truncation=True, max_length=512).to(self.device)
            with torch.no_grad():
                outputs = self.model(**inputs)
                return torch.nn.functional.softmax(outputs.logits, dim=-1).cpu().numpy()
        
        # Create explainer
        self.explainer = shap.Explainer(predictor, self.tokenizer)

    def explain(self, text):
        # Calculate SHAP values
        shap_values = self.explainer([text])
        
        # Get the predicted class index
        probs = self.classifier.predict(text)["probabilities"]
        classes = ['secure', 'misconfigured', 'secretLeakage', 'highRisk']
        pred_class = max(probs, key=probs.get)
        pred_idx = classes.index(pred_class)
        
        # Extract tokens and values for the predicted class
        tokens = shap_values.data[0].tolist()
        values = shap_values.values[0][:, pred_idx].tolist()
        base_value = float(shap_values.base_values[0][pred_idx])
        
        return {
            "tokens": tokens,
            "shapValues": values,
            "baseValue": base_value,
            "predictedClass": pred_class
        }
