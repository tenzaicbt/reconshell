
TIMING_PROFILES = {
    0: {'concurrency': 10, 'timeout': 5.0},
    1: {'concurrency': 50, 'timeout': 3.0},
    2: {'concurrency': 100, 'timeout': 1.5},
    3: {'concurrency': 200, 'timeout': 1.0},
    4: {'concurrency': 500, 'timeout': 0.5},
    5: {'concurrency': 1000, 'timeout': 0.3}
}

def get_timing_profile(level):
    return TIMING_PROFILES.get(level, TIMING_PROFILES[3])