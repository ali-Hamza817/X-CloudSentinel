import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
import os

class SentinelRemediator:
    """
    Experimental LLM-based Remediation Engine.
    Uses a small local model to suggest fixes for security findings.
    """
    def __init__(self, model_name="Salesforce/codegen-350M-mono"):
        print(f"Initializing Remediator with {model_name}...")
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Load a small code-specialized model
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForCausalLM.from_pretrained(model_name).to(self.device)
        self.model.eval()

    def suggest_fix(self, snippet, finding_title):
        prompt = f"// Security Finding: {finding_title}\n// Original insecure code:\n{snippet}\n// Secure version of the code:\n"
        
        inputs = self.tokenizer(prompt, return_tensors="pt").to(self.device)
        
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs, 
                max_new_tokens=150,
                temperature=0.2,
                top_p=0.9,
                repetition_penalty=1.1
            )
            
        decoded = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        # Extract the secure part after the prompt
        secure_code = decoded[len(prompt):].split('//')[0].strip()
        
        return {
            "original": snippet,
            "suggestedFix": secure_code,
            "explanation": f"LLM-generated secure alternative for: {finding_title}"
        }
