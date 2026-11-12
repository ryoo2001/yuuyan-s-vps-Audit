"""Shared age/access policy for all central audit regions."""
import os

POLICY_VERSION = 1
HOT_DAYS = int(os.environ.get('TRAFFIC_CENTRAL_HOT_DAYS', '7'))
ONLINE_DAYS = 14
ARCHIVE_ROOT = os.environ.get('TRAFFIC_CENTRAL_ARCHIVE', '/var/lib/traffic-central/archive')
if not 3 <= HOT_DAYS <= 7:
    raise ValueError('hot_days_must_be_between_three_and_seven')

def metadata():
    return {'version': POLICY_VERSION, 'hot_days': HOT_DAYS,
            'online_days': ONLINE_DAYS, 'cold_storage': 'monthly_files_outside_database',
            'archive_loading': 'explicit_only', 'hot_warm_layout': 'indexed_time_ranges',
            'monthly_summary': 'calendar_month_start_to_latest',
            'monthly_summary_storage': 'compact_current_month_totals_no_raw_restore'}
