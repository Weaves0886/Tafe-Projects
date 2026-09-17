import json
import hashlib
import sys

def produce_hash(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def load_json(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
    except json.JSONDecodeError:
        print(f"Invalid JSON format in file: {file_path}")
        return None
    except Exception as e:
        print(f"Error loading JSON file: {e}")
        return None

def load_rockyou(file_path):
    try:
        with open(file_path, 'r', encoding='latin-1') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
    except Exception as e:
        print(f"Error loading wordlist: {e}")
        return None

def get_valid_file(prompt_text, loader_func):
    """Keep asking until a valid file is provided. Type 'exit' or 'quit' to exit."""
    while True:
        file_path = input(prompt_text).strip()
        if not file_path:
            print("File path cannot be empty.")
            continue
        
        if file_path.lower() in ['exit', 'quit']:
            print("Exiting program.")
            sys.exit(0)
        
        data = loader_func(file_path)
        if data is not None:
            print(f"Successfully loaded: {file_path}")
            return file_path, data
        # If failed, loop again
        print("Please try again.\n")

def main():
    print("=== Password Audit Tool ===\n")
    
    # Get valid users file
    users_file, users = get_valid_file(
        "Enter the path to the users hashes JSON file (e.g. users_hashes.json): ",
        load_json
    )
    
    # Get valid rockyou file
    rockyou_file, common_pwds = get_valid_file(
        "Enter the path to the rockyou wordlist file (e.g. rockyou.txt): ",
        load_rockyou
    )
    
    print(f"\nLoaded {len(users)} users and {len(common_pwds):,} common passwords.")
    print("Starting password audit...\n")
    
    # Pre-hash common passwords for fast lookup
    common_hashes = {}
    for pwd in common_pwds:
        common_hashes[produce_hash(pwd)] = pwd
    
    results = []
    for user in users:
        username = user.get("user_name", "unknown")
        stored_hash = user.get("user_password")
        
        if stored_hash and stored_hash in common_hashes:
            results.append({
                "username": username,
                "password": common_hashes[stored_hash],
                "password_found": True
            })
        else:
            results.append({
                "username": username,
                "password": "",
                "password_found": False
            })
    
    # Save results
    output_file = "weak_passwords_findings.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    
    found = sum(1 for r in results if r["password_found"])
    print(f"=== Password Audit Complete ===")
    print(f"Found {found} weak passwords out of {len(users)} accounts.")
    print(f"Results saved to: {output_file}")

if __name__ == "__main__":
    main()
