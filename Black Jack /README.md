# Black Jack

A command-line Blackjack game built in Python, complete with token betting, 
a persistent winners log, and a custom twist — the "Barry" card.

## Features

- **Classic Blackjack rules** — hit or stand, dealer draws to 17, bust and tie logic
- **Token betting system** — start with 100 tokens, place bets (min 10) each round, 
  win or lose them based on the outcome
- **Special "Barry" card** — a 53rd card added to the deck; drawing it is an 
  instant win with a triple payout
- **Winners history** — every win is saved to a JSON file in your Documents 
  folder (`Blackjack/blackjack_winners.json`), so past wins persist between sessions
- **Menu-driven** — start a game, view winner history, or exit from a simple text menu
- **Input validation** — handles invalid bets, non-numeric input, and empty deck 
  reshuffling gracefully


You'll be prompted to enter your name, place bets, and play rounds until you 
run out of tokens or choose to stop.

## How it works

- `Card` / `Deck` — represent the 52 standard cards plus the special Barry card; 
  the deck is shuffled on creation
- `Player` — tracks a player's name, token balance, and current bet
- `BlackjackGame` — runs a single round: dealing, hit/stand logic, hand value 
  calculation (with Ace handling), and the dealer's turn
- `BlackjackMenu` — the entry point that loops the menu, starts games, and 
  displays saved winner data

## What I learned

- Structuring a program with multiple classes (`Card`, `Deck`, `Player`, `Game`, `Menu`) 
  instead of one big script
- Handling edge cases: empty bets, invalid input, an emptied deck mid-game
- Reading and writing JSON to persist data between program runs
- Cross-platform file path handling (`sys.platform` check for Windows vs. other OS)
