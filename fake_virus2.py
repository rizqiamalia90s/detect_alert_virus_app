import time
import os

def second_simulation():
    print("Program simulasi kedua berjalan...")
    counter = 0
    while True:
        # Hanya print counter dan sleep - 100% aman
        print(f"Counter: {counter}", end='\r')
        counter += 1
        time.sleep(1)

if __name__ == "__main__":
    second_simulation()