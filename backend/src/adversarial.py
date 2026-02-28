import base64
import random

class SentinelAdversarialTester:
    """
    Implements mutation strategies to test the robustness of security detectors.
    Includes Base64 encoding, string splitting, and concatenation obfuscation.
    """
    def __init__(self, ner_classifier):
        self.ner_classifier = ner_classifier

    def mutate_secret(self, secret):
        """
        Applies random mutation strategies to a secret string.
        """
        strategy = random.choice(["base64", "split", "concat", "hex"])
        
        if strategy == "base64":
            mutated = base64.b64encode(secret.encode()).decode()
            return mutated, "Base64 Obfuscation"
        
        elif strategy == "split":
            mid = len(secret) // 2
            mutated = f"{secret[:mid]}'+'{secret[mid:]}"
            return mutated, "String Splitting"
        
        elif strategy == "concat":
            # e.g., secret -> s.e.c.r.e.t
            mutated = ".".join(list(secret))
            return mutated, "Concatenation Obfuscation"
        
        elif strategy == "hex":
            mutated = secret.encode().hex()
            return mutated, "Hex Encoding"
            
        return secret, "Original"

    def run_robustness_test(self, test_secrets):
        """
        Runs a robustness audit: Mutates secrets and checks if the NER model can still detect them.
        """
        results = []
        for secret in test_secrets:
            mutated, strategy = self.mutate_secret(secret)
            # Check if NER can find the ORIGINAL or the MUTATED one
            # (In reality, obfuscation usually breaks NER, which is why this is a valid research metric)
            ner_findings = self.ner_classifier.predict_secrets(mutated)
            
            detected = False
            for f in ner_findings:
                if mutated in f['secret'] or secret in f['secret']:
                    detected = True
                    break
            
            results.append({
                "original": secret,
                "mutated": mutated,
                "strategy": strategy,
                "detected": detected
            })
            
        return results
