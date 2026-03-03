#!/usr/bin/env python3
# core/key_manager.py - Auto API Key Rotation

import os
import time

class KeyManager:
    def __init__(self):
        keys_env = os.environ.get("GROQ_API_KEYS", "")
        single   = os.environ.get("GROQ_API_KEY", "")

        if keys_env:
            self.keys = [k.strip() for k in keys_env.split(",") if k.strip()]
        elif single:
            self.keys = [single]
        else:
            self.keys = []

        self.current      = 0
        self.usage        = {i: 0 for i in range(len(self.keys))}
        self.daily_limit  = 95000  # Leave 5k buffer
        print(f"\033[92m[*] Key manager loaded {len(self.keys)} API key(s) — {len(self.keys) * 100}k tokens/day available.\033[0m")

    def get_key(self) -> str:
        if not self.keys:
            raise ValueError("No API keys found! Set GROQ_API_KEYS environment variable.")
        return self.keys[self.current]

    def track_usage(self, tokens_used: int):
        """Track token usage per key."""
        self.usage[self.current] = self.usage.get(self.current, 0) + tokens_used
        remaining = self.daily_limit - self.usage[self.current]
        if remaining < 5000:
            print(f"\033[93m[*] Key {self.current + 1} running low ({remaining} tokens left), pre-rotating...\033[0m")
            self.rotate()

    def rotate(self) -> str:
        """Switch to next available key."""
        original = self.current
        while True:
            self.current = (self.current + 1) % len(self.keys)
            if self.usage.get(self.current, 0) < self.daily_limit:
                print(f"\033[93m[*] Rotated to API key {self.current + 1}/{len(self.keys)}\033[0m")
                return self.keys[self.current]
            if self.current == original:
                print(f"\033[91m[!] All keys exhausted for today. Waiting 60s...\033[0m")
                time.sleep(60)
                self.usage = {i: 0 for i in range(len(self.keys))}
                return self.keys[self.current]

    def handle_rate_limit(self, wait_seconds: int = 60) -> str:
        """Called when rate limit hit — rotate or wait."""
        if len(self.keys) > 1:
            # Mark current key as exhausted
            self.usage[self.current] = self.daily_limit
            return self.rotate()
        else:
            print(f"\033[93m[!] Rate limit hit. Waiting {wait_seconds}s...\033[0m")
            print(f"\033[93m[!] Tip: Add more keys to GROQ_API_KEYS to avoid waiting.\033[0m")
            time.sleep(wait_seconds)
            return self.get_key()

    def status(self):
        """Print current key usage status."""
        print("\n\033[94m[Key Manager Status]\033[0m")
        for i, key in enumerate(self.keys):
            used      = self.usage.get(i, 0)
            remaining = self.daily_limit - used
            active    = " ← active" if i == self.current else ""
            print(f"  Key {i+1}: {used} used / {remaining} remaining{active}")
        print()

key_manager = KeyManager()
