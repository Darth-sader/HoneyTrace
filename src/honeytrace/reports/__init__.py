"""Report layer: timeline (Report A), profile (Report B), dashboard (HTML).

The report layer READS the incident store and evidence journal. It never
writes evidence and never infers facts independently of the journal.
"""

from honeytrace.reports.dashboard import DashboardServer, ReportRenderer, start_dashboard_thread
from honeytrace.reports.profile import ProfileBuilder
from honeytrace.reports.timeline import TimelineBuilder

__all__ = ["DashboardServer", "ReportRenderer", "ProfileBuilder", "TimelineBuilder", "start_dashboard_thread"]
