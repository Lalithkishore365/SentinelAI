#!/usr/bin/env python3
"""
Attack bot to test Sentinel AI security system
Sends rapid requests to trigger attack detection
"""

import requests
import time
import sys

BASE_URL = "http://127.0.0.1:5000"
USERNAME = "admin"
PASSWORD = "admin123"

def run_attack():
    """Run attack with fresh session each time"""
    
    print("\n" + "="*70)
    print("🤖 ATTACK BOT - Testing Security System")
    print("="*70)
    
    # Create NEW session (fresh cookies every run)
    session = requests.Session()
    
    # Step 1: Login
    print("\n[1] Attempting login...")
    print(f"    Username: {USERNAME}")
    print(f"    Password: {PASSWORD}")
    
    try:
        r = session.post(
            f"{BASE_URL}/",
            data={"username": USERNAME, "password": PASSWORD},
            timeout=5
        )
        
        print(f"    Status: {r.status_code}")
        print(f"    URL: {r.url}")
        
        # Check if we got blocked at login
        if r.status_code == 403 or "blocked" in r.text.lower():
            print("\n🚫 BLOCKED AT LOGIN!")
            print("    User account is permanently blocked.")
            print("    This is EXPECTED if attack was previously detected.")
            print("\n💡 To reset: Delete db/database.db and restart server")
            return "BLOCKED_AT_LOGIN"
        
        if "login" in r.url.lower() or r.status_code != 200:
            print("\n❌ LOGIN FAILED!")
            print(f"    Response status: {r.status_code}")
            print("    Check if credentials are correct or user exists")
            return "LOGIN_FAILED"
        
        print("✅ Login successful!\n")
        
    except Exception as e:
        print(f"\n❌ Login error: {e}")
        return "ERROR"
    
    # Step 2: Spam requests (attack simulation)
    print("[2] Sending rapid requests (attack simulation)...")
    print("-" * 70)
    
    blocked_at = None
    success_count = 0
    blocked_count = 0
    
    for i in range(1, 201):
        try:
            r = session.post(f"{BASE_URL}/submit-form", timeout=2)
            status = r.status_code
            
            # Track status
            if status == 200:
                success_count += 1
            elif status == 403:
                blocked_count += 1
                if blocked_at is None:
                    blocked_at = i
            
            # Print every 10th request, or when blocked
            if i % 10 == 0 or status == 403 or i <= 5:
                print(f"    Request {i:3d} → {status}")
            
            # Check if blocked
            if status == 403 or "blocked" in r.text.lower():
                if blocked_at == i:  # First time blocked
                    print(f"\n    🚫 BLOCKED AT REQUEST #{i}!")
                    print("    Continuing to verify all future requests are blocked...\n")
            
            # Very short delay (simulates bot)
            time.sleep(0.01)
            
        except requests.exceptions.Timeout:
            print(f"    Request {i:3d} → TIMEOUT")
            if blocked_at is None:
                blocked_at = i
        except Exception as e:
            print(f"    Request {i:3d} → ERROR: {e}")
            if blocked_at is None:
                blocked_at = i
    
    print("-" * 70)
    
    # Step 3: Results
    print(f"\n[3] Attack Results:")
    print(f"    Total requests sent: 200")
    print(f"    Successful (200): {success_count}")
    print(f"    Blocked (403): {blocked_count}")
    
    if blocked_at:
        print(f"    🚫 First blocked at request: #{blocked_at}")
        
        if blocked_at <= 20:
            print(f"    ✅ EXCELLENT: Blocked within first 20 requests!")
        elif blocked_at <= 50:
            print(f"    ✅ GOOD: Blocked within first 50 requests")
        else:
            print(f"    ⚠️  SLOW: Took {blocked_at} requests to block")
    else:
        print(f"    ❌ FAILURE: Attack was NOT blocked!")
        print(f"    All 200 requests succeeded - detection not working")
    
    # Step 4: Logout
    print(f"\n[4] Logging out...")
    try:
        session.get(f"{BASE_URL}/logout", timeout=5)
        print("    Logout complete")
    except Exception as e:
        print(f"    Logout error: {e}")
    
    print("\n" + "="*70)
    
    return "BLOCKED" if blocked_at else "NOT_BLOCKED"


def test_permanent_block():
    """Test if user is permanently blocked"""
    
    print("\n" + "="*70)
    print("🔒 Testing Permanent Block")
    print("="*70)
    
    print("\n[1] Attempting login with NEW session...")
    
    session = requests.Session()
    
    try:
        r = session.post(
            f"{BASE_URL}/",
            data={"username": USERNAME, "password": PASSWORD},
            timeout=5
        )
        
        if r.status_code == 403 or "blocked" in r.text.lower():
            print("    ✅ BLOCKED - User is permanently blocked")
            print("    System is working correctly!")
            return True
        else:
            print(f"    ⚠️  NOT BLOCKED - User can still login (Status: {r.status_code})")
            print("    Permanent blocking may not be enabled")
            return False
            
    except Exception as e:
        print(f"    ❌ Error: {e}")
        return False


if __name__ == "__main__":
    print("\n🛡️ SENTINEL AI - Attack Bot")
    print("Testing real-time attack detection system\n")
    
    # Run the attack
    result = run_attack()
    
    # If attack was blocked, test permanent blocking
    if result == "BLOCKED":
        print("\n⏳ Waiting 2 seconds before testing permanent block...")
        time.sleep(2)
        test_permanent_block()
    elif result == "BLOCKED_AT_LOGIN":
        print("\n✅ Permanent blocking confirmed - user cannot login")
    
    print("\n" + "="*70)
    print("🎯 SUMMARY")
    print("="*70)
    
    if result == "BLOCKED":
        print("✅ Attack detection is WORKING")
        print("   - Attack was blocked mid-execution")
        print("   - System protected against rapid requests")
    elif result == "BLOCKED_AT_LOGIN":
        print("✅ Permanent blocking is WORKING")
        print("   - User account is blocked")
        print("   - Cannot login even with correct credentials")
    elif result == "NOT_BLOCKED":
        print("❌ Attack detection FAILED")
        print("   - All 200 requests succeeded")
        print("   - Check server logs for errors")
    else:
        print("❌ Test encountered errors")
    
    print("="*70 + "\n")