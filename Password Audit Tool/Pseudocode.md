START

1.  Define file paths:
    - input_file = "users_hashes.json"
    - rockyou_file = "rockyou.txt"
    - output_file = "weak_passwords_findings.json"

2.  Try to open files:
    IF input_file does NOT exist OR cannot be read:
        Show error message
        Create output file with error details
        END

    IF rockyou_file does NOT exist OR cannot be read:
        Show error message
        Create output file with error details
        END

3.  Load users data from JSON file
4.  Load common passwords from rockyou.txt (using latin-1 encoding)

5.  Create empty list for results

6.  For each user in users data:
        Get username and stored_hash
        Hash all rockyou passwords (or use pre-hashed dictionary)
        IF stored_hash matches any common password hash:
            Add to results: {username, actual_password, password_found = True}
        ELSE:
            Add to results: {username, "", password_found = False}

7.  Save results list to output_file as JSON

8.  Print summary (number of weak passwords found)

9.  Catch any unexpected errors:
        Print error message
        Save error to output_file

