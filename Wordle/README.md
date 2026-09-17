# Guess My Word (Wordle Clone)

A command-line Wordle clone built in Python. Guess the hidden 5-letter 
word within 6 attempts.

## How it works

- `?` = letter is correct and in the right position
- `-` = letter is not correct

After each guess, your score and the word you guessed are displayed. 
Guess the word exactly (all `?`s) to win. If you run out of attempts, 
the correct word is revealed.

## Requirements

Two text files must be in the same folder as the script:
- **`target_words.txt`** — the pool of possible answer words the game 
  randomly picks from
- **`all_words.txt`** — the full list of valid words accepted as guesses

You'll be asked for your name, then shown a menu to play, view 
instructions, or exit. Type `exit` twice in a row during a game to quit 
early.

## Note

Written without f-strings (using `.format()` instead) due to a 
last-minute requirement from my teacher.

## What I learned

- String formatting without f-strings
- File I/O and validating word lists
- Input validation and loop control (menus, replay logic, exit conditions)
