import os
from huggingface_hub import HfApi

# --- CONFIGURATION ---
MY_HF_TOKEN = os.environ.get("HUGGINGFACE_TOKEN", "YOUR_TOKEN_HERE")
SPACE_ID = "qwlkjh/ExplainableCloudSentinel"
BASE_PATH = r"f:\Fullbright Scholarship\SentinelIQ\backend"

api = HfApi(token=MY_HF_TOKEN if MY_HF_TOKEN != "YOUR_TOKEN_HERE" else None)

def check_token():
    try:
        user_info = api.whoami()
        print(f"Token Owner: {user_info['name']}")
        print(f"Token Permissions: {user_info.get('auth', {}).get('accessToken', {}).get('role', 'unknown')}")
        return True
    except Exception as e:
        print(f"Failed to verify token: {str(e)}")
        return False

def upload_file_to_space(file_name):
    print(f"Uploading {file_name} to {SPACE_ID}...")
    local_path = os.path.join(BASE_PATH, file_name)
    if not os.path.exists(local_path):
        print(f"Error: {local_path} not found!")
        return
    try:
        api.upload_file(
            path_or_fileobj=local_path,
            path_in_repo=file_name,
            repo_id=SPACE_ID,
            repo_type="space"
        )
        print(f"Done: {file_name}")
    except Exception as e:
        print(f"Failed: {file_name} - {str(e)}")

def upload_folder_to_space(folder_name, ignore_patterns=None):
    print(f"Starting upload of {folder_name} to {SPACE_ID} (Optimized for 1GB limit)...")
    local_path = os.path.join(BASE_PATH, folder_name)
    
    if not os.path.exists(local_path):
        print(f"Error: {local_path} does not exist!")
        return

    try:
        api.upload_folder(
            folder_path=local_path,
            repo_id=SPACE_ID,
            repo_type="space",
            path_in_repo=folder_name,
            ignore_patterns=ignore_patterns
        )
        print(f"Successfully uploaded {folder_name}!")
    except Exception as e:
        print(f"Failed to upload {folder_name}: {str(e)}")

if __name__ == "__main__":
    if check_token():
        # 1. Upload individual files first
        for f in ["app.py", "Dockerfile", "requirements.txt"]:
            upload_file_to_space(f)
        
        # 2. Upload the logic
        upload_folder_to_space("src")
        
        # 3. Upload the heavy models (Skipping 4.5GB of training checkpoints)
        upload_folder_to_space("models", ignore_patterns=["*checkpoints*", "*.db", "backend.log"])
        
        print("\nALL DONE! Check your Space App tab.")
