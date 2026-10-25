"""Console entry point: `python -m honeytrace`.

The old version imported a dashboard module that did not exist and crashed
at startup. The dashboard now exists (honeytrace.reports.dashboard) and the
CLI owns all entry points.
"""

import sys

from honeytrace.cli import main

if __name__ == "__main__":
    sys.exit(main())
