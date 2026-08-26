"""Daily collection pipeline entrypoint wrapper.

Runs the collectors (URLhaus, AbuseIPDB) and updates threat statistics.
"""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from scripts.run_daily_collection import main

if __name__ == "__main__":
    main()
