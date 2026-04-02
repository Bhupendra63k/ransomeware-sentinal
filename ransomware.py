import os
import time
import random

# Use a safe test directory
TEST_FOLDER = os.path.expanduser("~/test_folder")

def simulate_ransomware():
    print("🚨 Starting SAFE ransomware simulation (Linux)...")

    # Ensure folder exists
    os.makedirs(TEST_FOLDER, exist_ok=True)

    files = []

    # Step 1: Create files
    for i in range(40):
        path = os.path.join(TEST_FOLDER, f"file_{i}.txt")
        with open(path, "w") as f:
            f.write("normal data\n")
        files.append(path)

    time.sleep(1)

    # Step 2: Rapid modification (simulate encryption activity)
    for path in files:
        with open(path, "a") as f:
            f.write(os.urandom(random.randint(500, 2000)).hex())
        time.sleep(0.03)

    # Step 3: Rename files (simulate ransomware extension)
    for path in files:
        new_path = path + ".encrypted"
        try:
            os.rename(path, new_path)
        except Exception as e:
            print("Rename error:", e)
        time.sleep(0.03)

    print("⚠️ Simulation complete (safe test)")

if __name__ == "__main__":
    simulate_ransomware()