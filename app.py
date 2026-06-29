#!/usr/bin/env python3
"""
Password Strength Analyzer
A comprehensive tool for evaluating password strength with suggestions and history tracking.
"""

import re
import hashlib
import secrets
import string
import json
import os
from datetime import datetime
from typing import Dict, List, Tuple, Optional

class PasswordDatabase:
    """Simple file-based database to track password history and prevent reuse."""
    
    def __init__(self, db_file: str = "password_history.json"):
        self.db_file = db_file
        self.history = self._load_database()
    
    def _load_database(self) -> Dict:
        """Load password history from JSON file."""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {"passwords": []}
        return {"passwords": []}
    
    def _save_database(self) -> None:
        """Save password history to JSON file."""
        with open(self.db_file, 'w') as f:
            json.dump(self.history, f, indent=2)
    
    def add_password(self, password: str) -> None:
        """Add a hashed password to the history."""
        # Store SHA-256 hash instead of plaintext
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        self.history["passwords"].append({
            "hash": password_hash,
            "timestamp": datetime.now().isoformat(),
            "length": len(password)
        })
        
        # Keep only last 100 passwords
        if len(self.history["passwords"]) > 100:
            self.history["passwords"] = self.history["passwords"][-100:]
        
        self._save_database()
    
    def is_password_used_before(self, password: str) -> bool:
        """Check if password has been used before."""
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return any(entry["hash"] == password_hash for entry in self.history["passwords"])
    
    def get_password_count(self) -> int:
        """Get total number of passwords in history."""
        return len(self.history["passwords"])


class PasswordStrengthAnalyzer:
    """Main password analysis class with strength evaluation and suggestions."""
    
    # Common weak passwords (abbreviated list)
    COMMON_PASSWORDS = {
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
        'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
        'bailey', 'shadow', '123123', '654321', 'superman',
        'qazwsx', 'michael', 'football', 'admin', 'welcome'
    }
    
    def __init__(self, db_file: str = "password_history.json"):
        self.database = PasswordDatabase(db_file)
    
    def analyze_password(self, password: str) -> Dict:
        """
        Comprehensive password analysis.
        Returns a dictionary with strength metrics and suggestions.
        """
        if not password:
            return {
                "strength": "No Password",
                "score": 0,
                "feedback": ["Please enter a password."],
                "suggestions": []
            }
        
        # Calculate various metrics
        length = len(password)
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_numbers = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        has_mixed_case = has_uppercase and has_lowercase
        
        # Count character types
        char_types = sum([has_uppercase, has_lowercase, has_numbers, has_special])
        
        # Check for patterns
        has_sequential = bool(re.search(r'(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)', password.lower()))
        has_repeated = bool(re.search(r'(.)\1{2,}', password))
        
        # Calculate entropy score
        entropy = self._calculate_entropy(password)
        
        # Calculate strength score (0-100)
        score = 0
        feedback = []
        
        # Length scoring (up to 30 points)
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 25
            feedback.append("Good length, but 16+ characters would be stronger.")
        elif length >= 8:
            score += 15
            feedback.append("Consider using a longer password (at least 12 characters).")
        else:
            score += 5
            feedback.append("Password is too short. Use at least 8 characters.")
        
        # Complexity scoring (up to 40 points)
        score += char_types * 10
        
        if not has_uppercase:
            feedback.append("Add uppercase letters for better security.")
        if not has_lowercase:
            feedback.append("Add lowercase letters for better security.")
        if not has_numbers:
            feedback.append("Add numbers for better security.")
        if not has_special:
            feedback.append("Add special characters (!@#$%^&*) for better security.")
        if not has_mixed_case:
            feedback.append("Mix uppercase and lowercase letters.")
        
        # Entropy bonus (up to 15 points)
        if entropy > 4:
            score += 15
        elif entropy > 3:
            score += 10
        elif entropy > 2:
            score += 5
        
        # Penalties
        if has_sequential:
            score -= 10
            feedback.append("Avoid sequential characters (like 'abc' or '123').")
        
        if has_repeated:
            score -= 10
            feedback.append("Avoid repeated characters (like 'aaa' or '111').")
        
        # Common password check
        is_common = password.lower() in self.COMMON_PASSWORDS
        if is_common:
            score -= 25
            feedback.append("This is a commonly used password and easily guessable.")
        
        # Check if password contains personal info patterns (simple checks)
        if re.search(r'(19|20)\d{2}', password):
            score -= 5
            feedback.append("Avoid using years in your password.")
        
        # Password history check
        is_reused = self.database.is_password_used_before(password)
        if is_reused:
            score -= 15
            feedback.append("You've used this password before. Please choose a new one.")
        
        # Ensure score stays within 0-100
        score = max(0, min(100, score))
        
        # Determine strength category
        if score >= 80:
            strength = "Very Strong"
        elif score >= 60:
            strength = "Strong"
        elif score >= 40:
            strength = "Moderate"
        elif score >= 20:
            strength = "Weak"
        else:
            strength = "Very Weak"
        
        # Generate suggestions
        suggestions = self._generate_suggestions(password, length)
        
        return {
            "strength": strength,
            "score": score,
            "entropy": round(entropy, 2),
            "length": length,
            "character_types": char_types,
            "has_uppercase": has_uppercase,
            "has_lowercase": has_lowercase,
            "has_numbers": has_numbers,
            "has_special": has_special,
            "is_common": is_common,
            "is_reused": is_reused,
            "feedback": feedback,
            "suggestions": suggestions
        }
    
    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy (bits of entropy per character)."""
        if not password:
            return 0
        
        # Determine character pool size
        pool_size = 0
        if re.search(r'[a-z]', password):
            pool_size += 26
        if re.search(r'[A-Z]', password):
            pool_size += 26
        if re.search(r'\d', password):
            pool_size += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            pool_size += 20
        
        if pool_size == 0:
            return 0
        
        # Calculate bits of entropy
        import math
        entropy = math.log2(pool_size ** len(password))
        return entropy / len(password)  # Return entropy per character
    
    def _generate_suggestions(self, password: str, current_length: int) -> List[str]:
        """Generate strong password alternatives based on the input."""
        suggestions = []
        
        # Generate 3 different types of suggestions
        for _ in range(3):
            suggested = self._generate_strong_password(password, current_length)
            suggestions.append(suggested)
        
        return suggestions
    
    def _generate_strong_password(self, base_password: str, target_length: int) -> str:
        """Generate a strong password alternative."""
        # Use secrets module for cryptographically secure random generation
        if target_length < 12:
            target_length = 16
        elif target_length < 16:
            target_length += 4
        
        # Character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*"
        
        # Ensure at least one of each type
        password_chars = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]
        
        # Fill the rest with random characters
        all_chars = lowercase + uppercase + digits + special
        for _ in range(target_length - 4):
            password_chars.append(secrets.choice(all_chars))
        
        # Shuffle the characters
        secrets.SystemRandom().shuffle(password_chars)
        
        return ''.join(password_chars)
    
    def get_strength_bar(self, score: int) -> str:
        """Visual representation of password strength."""
        if score >= 80:
            return "██████████ Very Strong"
        elif score >= 60:
            return "████████░░ Strong"
        elif score >= 40:
            return "██████░░░░ Moderate"
        elif score >= 20:
            return "████░░░░░░ Weak"
        else:
            return "██░░░░░░░░ Very Weak"


def display_banner():
    """Display the program banner."""
    banner = """
    ╔══════════════════════════════════════════════════════╗
    ║           PASSWORD STRENGTH ANALYZER                 ║
    ║           Security Assessment Tool                   ║
    ╚══════════════════════════════════════════════════════╝
    """
    print(banner)


def display_cryptography_info():
    """Display basic cryptography concepts related to password security."""
    info = """
    ┌──────────────────────────────────────────────────────┐
    │          PASSWORD SECURITY & CRYPTOGRAPHY             │
    ├──────────────────────────────────────────────────────┤
    │                                                       │
    │  • Hashing: Passwords are stored as hashes (SHA-256) │
    │    One-way function, cannot be reversed              │
    │                                                       │
    │  • Salt: Random data added to passwords before       │
    │    hashing to prevent rainbow table attacks          │
    │                                                       │
    │  • Entropy: Measure of randomness/unpredictability   │
    │    Higher entropy = stronger password               │
    │                                                       │
    │  • Key Stretching: Techniques like PBKDF2, bcrypt    │
    │    to make brute-force attacks slower                │
    │                                                       │
    └──────────────────────────────────────────────────────┘
    """
    print(info)


def main():
    """Main program loop."""
    display_banner()
    
    analyzer = PasswordStrengthAnalyzer()
    
    while True:
        print("\n" + "="*55)
        print("MAIN MENU")
        print("="*55)
        print("1. Analyze a Password")
        print("2. View Cryptography Info")
        print("3. View Password History Stats")
        print("4. Generate Strong Password")
        print("5. Exit")
        print("="*55)
        
        choice = input("Enter your choice (1-5): ").strip()
        
        if choice == '1':
            print("\n" + "-"*55)
            print("PASSWORD ANALYSIS")
            print("-"*55)
            print("Tips for strong passwords:")
            print("  • At least 16 characters long")
            print("  • Mix of uppercase, lowercase, numbers, and symbols")
            print("  • No personal information or common words")
            print("  • Unique (not used for other accounts)")
            print("-"*55)
            
            password = input("\nEnter password to analyze: ").strip()
            
            if not password:
                print("\n⚠️  No password entered!")
                continue
            
            # Analyze password
            results = analyzer.analyze_password(password)
            
            # Display results
            print("\n" + "="*55)
            print("ANALYSIS RESULTS")
            print("="*55)
            print(f"\n📊 Strength: {results['strength']} (Score: {results['score']}/100)")
            print(f"📈 Strength Bar: {analyzer.get_strength_bar(results['score'])}")
            print(f"\n📏 Length: {results['length']} characters")
            print(f"🔢 Character Types: {results['character_types']} of 4")
            print(f"📐 Entropy: {results['entropy']} bits per character")
            
            print(f"\n✓ Contains Uppercase: {'Yes' if results['has_uppercase'] else 'No'}")
            print(f"✓ Contains Lowercase: {'Yes' if results['has_lowercase'] else 'No'}")
            print(f"✓ Contains Numbers: {'Yes' if results['has_numbers'] else 'No'}")
            print(f"✓ Contains Special Chars: {'Yes' if results['has_special'] else 'No'}")
            print(f"⚠️  Common Password: {'Yes' if results['is_common'] else 'No'}")
            print(f"⚠️  Previously Used: {'Yes' if results['is_reused'] else 'No'}")
            
            if results['feedback']:
                print("\n💡 FEEDBACK:")
                for i, feedback in enumerate(results['feedback'], 1):
                    print(f"  {i}. {feedback}")
            
            if results['suggestions']:
                print("\n🔐 SUGGESTED STRONGER PASSWORDS:")
                for i, suggestion in enumerate(results['suggestions'], 1):
                    print(f"  {i}. {suggestion}")
            
            # Option to save password to history
            save = input("\n💾 Save this password to history? (y/n): ").strip().lower()
            if save == 'y':
                analyzer.database.add_password(password)
                print("✅ Password saved to history (as hash only)")
        
        elif choice == '2':
            display_cryptography_info()
        
        elif choice == '3':
            count = analyzer.database.get_password_count()
            print(f"\n📚 PASSWORD HISTORY")
            print(f"   Total passwords analyzed: {count}")
            print(f"   Note: Only SHA-256 hashes are stored, not plaintext passwords")
            
            if count > 0:
                print(f"\n   Recent activity:")
                for i, entry in enumerate(analyzer.database.history["passwords"][-5:], 1):
                    print(f"   {i}. Hash: {entry['hash'][:16]}... | "
                          f"Length: {entry['length']} | "
                          f"Date: {entry['timestamp'][:10]}")
        
        elif choice == '4':
            print("\n🔨 PASSWORD GENERATOR")
            length = input("Enter desired password length (recommended: 16+): ").strip()
            
            try:
                length = int(length)
                if length < 8:
                    print("⚠️  Minimum length is 8 characters. Setting to 16.")
                    length = 16
            except ValueError:
                print("⚠️  Invalid input. Using default length of 16.")
                length = 16
            
            # Generate a random strong password
            chars = string.ascii_letters + string.digits + "!@#$%^&*"
            generated = ''.join(secrets.choice(chars) for _ in range(length))
            
            print(f"\n✅ Generated Password: {generated}")
            print("   This password is random and meets complexity requirements.")
        
        elif choice == '5':
            print("\n👋 Thank you for using Password Strength Analyzer!")
            print("   Stay safe online! 🔒")
            break
        
        else:
            print("\n❌ Invalid choice. Please enter a number between 1 and 5.")
        
        # Pause before showing menu again
        if choice != '5':
            input("\n⏎ Press Enter to continue...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Program interrupted. Goodbye!")
    except Exception as e:
        print(f"\n❌ An error occurred: {e}")
