import requests
import time

URL = "http://localhost:5000/analyze"
TEST_LINK = "https://google.com"

def test_caching():
    print(f"Testing caching for {TEST_LINK}...")
    
    # First request
    start = time.time()
    resp1 = requests.post(URL, json={"url": TEST_LINK})
    end = time.time()
    print(f"First request took: {end - start:.2f}s")
    if resp1.status_code == 200:
        print("First request successful.")
    else:
        print(f"First request failed: {resp1.text}")
        return

    # Second request (should be cached)
    start = time.time()
    resp2 = requests.post(URL, json={"url": TEST_LINK})
    end = time.time()
    print(f"Second request took: {end - start:.2f}s")
    
    if resp2.status_code == 200:
        data = resp2.json()
        if data.get("cached"):
            print("SUCCESS: Second request was CACHED.")
        else:
            print("FAILURE: Second request was NOT CACHED.")
    else:
        print(f"Second request failed: {resp2.text}")

if __name__ == "__main__":
    test_caching()
