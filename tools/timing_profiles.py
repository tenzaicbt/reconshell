# Timing profiles like nmap -T0 to T5
TIMING_PROFILES = {
    0: {'concurrency': 10, 'timeout': 5.0},  # Paranoid
    1: {'concurrency': 50, 'timeout': 3.0},  # Sneaky
    2: {'concurrency': 100, 'timeout': 1.5}, # Polite
    3: {'concurrency': 200, 'timeout': 1.0}, # Normal
    4: {'concurrency': 500, 'timeout': 0.5}, # Aggressive
    5: {'concurrency': 1000, 'timeout': 0.3} # Insane
}

def get_timing_profile(level):
    return TIMING_PROFILES.get(level, TIMING_PROFILES[3])