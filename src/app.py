# Shift-Left Sentinel Sample App
import os

def main():
    # TEST: Hardcoded secret (Semgrep should find this)
    API_KEY = "12345-ABCDE-SECRET-KEY" 
    
    print("Application is running...")
    print(f"Connecting to service with key: {API_KEY}")

if __name__ == "__main__":
    main()
