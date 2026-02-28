import requests
import json

BASE_URL = 'http://127.0.0.1:5000'

def run_real_demo():
    print('--- REAL X-CloudSentinel OUTPUT DEMO ---')
    
    # 1. Check Health
    print('\n[1] Checking Intelligence Layer Health...')
    health = requests.get(f'{BASE_URL}/health').json()
    print(json.dumps(health, indent=2))
    
    # 2. Run Real Analysis on the user's current file
    print('\n[2] Analyzing: f:/Fullbright Scholarship/X-CloudSentinel/test-samples/insecure-terraform.tf')
    with open('f:/Fullbright Scholarship/X-CloudSentinel/test-samples/insecure-terraform.tf', 'r') as f:
        code = f.read()
    
    analyze_data = {'text': code, 'filePath': 'test-samples/insecure-terraform.tf'}
    ai_result = requests.post(f'{BASE_URL}/analyze', json=analyze_data).json()
    
    print('\n--- REAL AI CLASSIFICATION ---')
    print(f"RISK CLASS: {ai_result['prediction']}")
    print(f"CONFIDENCE: {ai_result['confidence']:.2%}")
    
    # 3. Get SHAP Explanation
    print('\n[3] Generating Explainable AI (SHAP) Heatmap...')
    explain_data = {'text': code[:500]}
    explain_result = requests.post(f'{BASE_URL}/explain', json=explain_data).json()
    print(f"Top detected risk tokens: {explain_result['tokens'][:5]}")
    
    # 4. Success
    print('\n--- DEMO COMPLETE: SYSTEM IS FULLY OPERATIONAL ---')

if __name__ == '__main__':
    try:
        run_real_demo()
    except Exception as e:
        print(f'Error: {e}')

