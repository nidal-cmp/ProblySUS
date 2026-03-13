import requests
import time
import sys

URL = "http://localhost:5000/analyze"

def run_test(url_variation, expected_cached=False):
    print(f"Testing: {url_variation} (Expected cached: {expected_cached})")
    try:
        resp = requests.post(URL, json={"url": url_variation})
        if resp.status_code != 200:
            print(f"  FAILED: Status {resp.status_code}")
            return None
        
        data = resp.json()
        is_cached = data.get("cached", False)
        score = data.get("riskScore")
        
        if expected_cached and not is_cached:
            print(f"  FAILED: Expected cached result, but got fresh scan.")
        elif not expected_cached and is_cached:
             print(f"  NOTE: Got cached result (maybe from previous run).")
        else:
            print(f"  SUCCESS: Cached status as expected ({is_cached}). Score: {score}")
            
        return score
    except Exception as e:
        print(f"  ERROR: {e}")
        return None

def test_normalization():
    print("--- Starting Normalization & Cache Consistency Test ---")
    
    # 1. Base URL
    score1 = run_test("https://example.com", expected_cached=False)
    
    # 2. Variation: Trailing slash
    score2 = run_test("https://example.com/", expected_cached=True)
    
    # 3. Variation: Uppercase
    score3 = run_test("HTTPS://EXAMPLE.COM", expected_cached=True)
    
    # 4. Variation: No protocol
    score4 = run_test("example.com", expected_cached=True)

    scores = [score1, score2, score3, score4]
    if all(s is not None for s in scores) and len(set(scores)) == 1:
        print("\n✅ ALL VARIATIONS RETURNED IDENTICAL SCORES.")
    else:
        print("\n❌ SCORE MISMATCH OR ERROR DETECTED.")
        print(f"Scores: {scores}")
        sys.exit(1)

if __name__ == "__main__":
    test_normalization()
