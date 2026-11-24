"""Shared age/access policy for all central audit regions."""
import os

POLICY_VERSION = 1
HOT_DAYS = int(os.environ.get('TRAFFIC_CENTRAL_HOT_DAYS', '7'))
ONLINE_DAYS = 14
# 2026-11-23: the four large raw tables stay on local disk for 48 h only; older
# rows move to the remote cold archive. Small tables keep ONLINE_DAYS.
RAW_HOT_HOURS = 48
RAW_HOT_TABLES = ('samples', 'visits', 'connection_state', 'connection_rates')
HOURLY_TOTALS_DAYS = 62
ARCHIVE_ROOT = os.environ.get('TRAFFIC_CENTRAL_ARCHIVE', '/var/lib/traffic-central/archive')
if not 3 <= HOT_DAYS <= 7:
    raise ValueError('hot_days_must_be_between_three_and_seven')


def archive_cutoff(name, now):
    """Rows of `name` older than this leave the database."""
    return now - (RAW_HOT_HOURS * 3600 if name in RAW_HOT_TABLES else ONLINE_DAYS * 86400)


def metadata():
    return {'version': POLICY_VERSION, 'hot_days': HOT_DAYS,
            'online_days': ONLINE_DAYS, 'raw_hot_hours': RAW_HOT_HOURS,
            'raw_hot_tables': list(RAW_HOT_TABLES), 'hourly_totals_days': HOURLY_TOTALS_DAYS,
            'cold_storage': 'monthly_files_outside_database', 'cold_chunking': 'beijing_day',
            'archive_loading': 'explicit_only', 'hot_warm_layout': 'indexed_time_ranges',
            'monthly_summary': 'calendar_month_start_to_latest',
            'monthly_summary_storage': 'compact_current_month_totals_no_raw_restore'}
