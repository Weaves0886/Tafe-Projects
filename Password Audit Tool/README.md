# Password Audit Tool

A command-line tool that checks a set of user password hashes against 
the RockYou wordlist to find accounts using common, weak passwords.

## How it works

1. Loads a JSON file of usernames and their SHA-256 password hashes
2. Loads the RockYou wordlist (a list of commonly used passwords)
3. Hashes every password in the wordlist and checks it against each 
   user's stored hash
4. Saves the results to a JSON file, showing which users had a password 
   found in the common password list

## Files in this project

- **`password_audit.py`** — the main script
- **`pseudocode.docx`** — planning pseudocode written before coding
- **`sample_users_hashes.json`** — example input file (fake users and hashes)
- **`sample_weak_passwords_findings.json`** — example output file, 
  showing the results format (fake data)

## Requirements

- **Users file** — a JSON file where each entry has a `user_name` and a 
  `user_password` (SHA-256 hash), e.g.:
```json
  {
    "user_name": "example_user",
    "user_password": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d"
  }
```
- **RockYou wordlist** — a plain text file of common passwords, one per 
  line (`rockyou.txt`). Not included in this repo due to size — 
  commonly available via SecLists on GitHub or bundled with Kali Linux

## How to run

```bash
python password_audit.py
```

You'll be prompted to enter the path to your users file and the RockYou 
wordlist. The tool keeps asking until valid files are given (type `exit` 
or `quit` to stop).

## Output

A file called `weak_passwords_findings.json` is created, listing each 
username, whether a matching weak password was found, and what it was.

## What I learned

- Hashing with `hashlib` (SHA-256)
- Reading and validating JSON and plain text files with different encodings
- Building a dictionary for fast lookups instead of comparing every 
  password one by one
- Input validation loops
- Planning with pseudocode before writing code
