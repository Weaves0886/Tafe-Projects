import random
import json
from datetime import datetime
import os
import sys
# Contains information about a card that can be played in the game
class Card:
    def __init__(self, suit, value):
        self.suit = suit
        self.value = value
    def __str__(self):
        return f"{self.value} of {self.suit}"
# Deck object includes an array of Cards objects depending on suits & values defined
#When the class is called in main, it declares an array of Card objects corresponding to the suits & values array
#for each suit, there exists a card of each value
class Deck:
    def __init__(self):
        suits = ['Hearts', 'Diamonds', 'Clubs', 'Spades']
        values = ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A']
        self.cards = [Card(suit, value) for suit in suits for value in values]
        self.cards.append(Card('Special', 'Barry'))  # Add special Barry card
        random.shuffle(self.cards)
    def draw(self):
        if len(self.cards) > 0:
            return self.cards.pop()
        return None
class Player:
    def __init__(self, name, tokens=100):
        self.name = name.strip()
        self.tokens = max(0, int(tokens))  # validates non-negative tokens
        self.current_bet = 0
    def place_bet(self, amount):
        try:
            amount = max(0, int(amount))  # validates non-negative bet
            if amount > self.tokens:
                return False
            self.current_bet = amount
            self.tokens -= amount
            return True
        except Exception:
            return False

    def win_bet(self, multiplier=2):
        try:
            self.tokens += self.current_bet * multiplier
            self.current_bet = 0
        except Exception:
            self.current_bet = 0

    def lose_bet(self):
        self.current_bet = 0


class BlackjackGame:
    def __init__(self):
        self.deck = Deck()
        self.player_hand = []
        self.dealer_hand = []
        self.winners_file = self.get_winners_file_path()
        self.winners = []
        self.load_winners()

    def get_winners_file_path(self):
        try:
            if sys.platform == "win32":
                documents = os.path.join(os.path.expanduser("~"), "Documents")
            else:
                documents = os.path.expanduser("~/Documents")
            
            game_dir = os.path.join(documents, "Blackjack")
            os.makedirs(game_dir, exist_ok=True)
            return os.path.join(game_dir, "blackjack_winners.json")
        except Exception:
            return "blackjack_winners.json"

    def load_winners(self):
        try:
            if os.path.exists(self.winners_file):
                with open(self.winners_file, 'r') as f:
                    self.winners = json.load(f)
        except Exception:
            self.winners = []

    def save_winner(self, player, win_type, bet_amount):
        try:
            winner_entry = {
                'name': player.name,
                'win_type': win_type,
                'bet_amount': bet_amount,
                'tokens_after_win': player.tokens,
                'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            self.winners.append(winner_entry)
            with open(self.winners_file, 'w') as f:
                json.dump(self.winners, f, indent=4)
        except Exception as e:
            print(f"Could not save winner data: {e}")

    def calculate_hand(self, hand):
        try:
            value = 0
            aces = 0
            
            for card in hand:
                if card.value == 'Barry':
                    return 21  # Barry card automatically wins
                elif card.value in ['J', 'Q', 'K']:
                    value += 10
                elif card.value == 'A':
                    aces += 1
                else:
                    value += int(card.value)
            
            for _ in range(aces):
                if value + 11 <= 21:
                    value += 11
                else:
                    value += 1
                    
            return value
        except Exception:
            return 0

    def get_valid_bet(self, player):
        while True:
            try:
                print(f"\nYou have {player.tokens} tokens")
                if player.tokens < 10:
                    print("Sorry, you don't have enough tokens to play!")
                    return None
                
                bet = input(f"Enter your bet (minimum 10, maximum {player.tokens}): ").strip()
                if not bet:
                    print("Please enter a bet amount!")
                    continue
                    
                bet = int(bet)
                
                if bet < 10:
                    print("Minimum bet is 10 tokens!")
                    continue
                if bet > player.tokens:
                    print("You don't have enough tokens!")
                    continue
                
                return bet
            except ValueError:
                print("Please enter a valid number!")
            except KeyboardInterrupt:
                print("\nGame cancelled.")
                sys.exit(0)

    def play(self, player):
        try:
            bet = self.get_valid_bet(player)
            if bet is None:
                return False

            if not player.place_bet(bet):
                print("Error placing bet!")
                return False

            print(f"\nBet placed: {bet} tokens")

            self.deck = Deck()  # Reset deck each game
            self.player_hand = [self.deck.draw(), self.deck.draw()]
            self.dealer_hand = [self.deck.draw(), self.deck.draw()]

            # Check for Barry card in initial hand
            for card in self.player_hand:
                if card.value == 'Barry':
                    print(f"Congratulations! You drew the Barry card! Instant win!")
                    player.win_bet(3)  # Triple payout
                    self.save_winner(player, "Barry Card", bet)
                    return True

            # Player's turn
            while True:
                print("\nYour hand:", [str(card) for card in self.player_hand])
                print("Dealer's visible card:", str(self.dealer_hand[0]))
                player_value = self.calculate_hand(self.player_hand)
                print(f"Your hand value: {player_value}")
                
                if player_value > 21:
                    print("Bust! You lose!")
                    player.lose_bet()
                    return True
                
                while True:
                    try:
                        choice = input("Do you want to hit (H) or stand (S)? ").upper().strip()
                        if choice in ['H', 'S']:
                            break
                        print("Please enter H or S!")
                    except KeyboardInterrupt:
                        print("\nGame cancelled.")
                        sys.exit(0)

                if choice == 'H':
                    new_card = self.deck.draw()
                    if new_card is None:
                        print("Deck empty, reshuffling.")
                        self.deck = Deck()
                        new_card = self.deck.draw()
                    self.player_hand.append(new_card)
                    print(f"You drew: {new_card}")
                    if new_card.value == 'Barry':
                        print("Congratulations! You drew the Barry card! Instant win!")
                        player.win_bet(3)
                        self.save_winner(player, "Barry Card", bet)
                        return True
                else:
                    break

            # Dealer's turn
            print("\nDealer's hand:", [str(card) for card in self.dealer_hand])
            while self.calculate_hand(self.dealer_hand) < 17:
                new_card = self.deck.draw()
                if new_card is None:
                    print("Deck empty, reshuffling.")
                    self.deck = Deck()
                    new_card = self.deck.draw()
                self.dealer_hand.append(new_card)
                print("Dealer draws:", str(new_card))

            player_value = self.calculate_hand(self.player_hand)
            dealer_value = self.calculate_hand(self.dealer_hand)

            print(f"\nYour final hand ({player_value}):", [str(card) for card in self.player_hand])
            print(f"Dealer's final hand ({dealer_value}):", [str(card) for card in self.dealer_hand])

            if dealer_value > 21:
                print("Dealer busts! You win!")
                player.win_bet()
                self.save_winner(player, "Regular Win", bet)
            elif player_value > dealer_value:
                print("You win!")
                player.win_bet()
                self.save_winner(player, "Regular Win", bet)
            elif player_value < dealer_value:
                print("Dealer wins!")
                player.lose_bet()
            else:
                print("It's a tie!")
                player.tokens += player.current_bet
                player.current_bet = 0

            print(f"\nYou now have {player.tokens} tokens")
            return True
            
        except Exception as e:
            print(f"An error occurred: {e}")
            player.tokens += player.current_bet
            player.current_bet = 0
            return False

class BlackjackMenu:
    def __init__(self):
        self.game = None

    def display_menu(self):
        while True:
            print("\n" + "="*50)
            print("Welcome to Blackjack!")
            print("1. Start Game")
            print("2. View Winners")
            print("3. Exit")
            print("="*50)

            choice = input("Select an option (1-3): ").strip()
            if choice == '1':
                self.start_game()
            elif choice == '2':
                self.view_winners()
            elif choice == '3':
                print("\nThanks for playing! Goodbye!")
                sys.exit(0)
            else:
                print("Invalid choice. Please select a valid option.")

    def start_game(self):
        player_name = input("Enter your name: ").strip()
        if not player_name:
            print("Please enter a valid name!")
            return
        
        player = Player(player_name)
        self.game = BlackjackGame()

        while player.tokens >= 10:
            print("\n" + "="*50)
            if not self.game.play(player):
                continue
            
            if player.tokens < 10:
                print("\nSorry, you don't have enough tokens to continue playing!")
                break
            
            while True:
                try:
                    play_again = input("\nWould you like to play again? (Y/N) ").upper().strip()
                    if play_again in ['Y', 'N']:
                        break
                    print("Please enter Y or N!")
                except KeyboardInterrupt:
                    print("\nGame cancelled.")
                    sys.exit(0)
                
            if play_again != 'Y':
                break

        print(f"\nGame Over! You finished with {player.tokens} tokens")

    def view_winners(self):
        if self.game:
            self.game.load_winners()
            if self.game.winners:
                print("\nWinners History:")
                for winner in self.game.winners:
                    print(f"{winner['name']} won {winner['bet_amount']} tokens on {winner['date']}")
            else:
                print("\nNo winners yet!")
        else:
            print("\nNo game has been played yet.")


def main():
    try:
        menu = BlackjackMenu()
        menu.display_menu()
    except KeyboardInterrupt:
        print("\nGame cancelled.")
        sys.exit(0)
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
