"""Narrow reviewed patches against captured live sources; no remote execution."""
import ast
import re

def patch_receiver(source):
    tree=ast.parse(source);functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
    node=functions['prune'];lines=source.splitlines(keepends=True)
    lines[node.lineno-1:node.end_lineno]=['def prune(db):\n    """Archive worker owns expiry; publishers must never delete first."""\n    return 0\n']
    source=''.join(lines)
    old='    cutoff = time.time() - 7 * 86400\n'
    if source.count(old)!=1:raise ValueError('receiver_cutoff_anchor_changed')
    source=source.replace(old,'',1)
    old='            if timestamp and values[columns.index(timestamp)] is not None and values[columns.index(timestamp)] < cutoff:\n                continue\n'
    if source.count(old)!=1:raise ValueError('receiver_age_filter_anchor_changed')
    source=source.replace(old,'',1)
    if source.count('SELECT epoch FROM')!=1:raise ValueError('receiver_state_anchor_changed')
    source=source.replace('SELECT epoch FROM','SELECT epoch,last_seq FROM',1)
    old="        for seq, table, values in payload['rows']:\n"
    if source.count(old)!=1:raise ValueError('receiver_batch_anchor_changed')
    source=source.replace(old,old+"            if state and seq <= state[1]:\n                continue\n",1)
    source=re.sub(r"('retention_days'\s*:\s*)7\b",r'\g<1>ONLINE_DAYS',source)
    position=source.index('from model import ')
    source=source[:position]+'from tier_policy import ONLINE_DAYS\n'+source[position:]
    compile(source,'receiver-candidate','exec');return source

def patch_reader(source):
    if 'def run(args):' not in source:raise ValueError('reader_anchor_changed')
    source=re.sub(r"('retention_days'\s*:\s*)7\b",r'\g<1>ONLINE_DAYS',source)
    source=source.replace('now-7*86400','now-ONLINE_DAYS*86400')
    source=source.replace('requested_window_precedes_seven_day_retention','requested_window_requires_explicit_cold_archive')
    source=source.replace('YYYY/MM/01–YYYY/MM/DD','YYYY/MM/DD–YYYY/MM/DD')
    anchor='    db=connect()'
    if source.count(anchor)!=1:raise ValueError('reader_connect_anchor_changed')
    source=source.replace(anchor,"    out['storage_tiers']=tier_metadata()\n"+anchor,1)
    if 'def _read_details(' in source:
        old='    where, params = [], []'
        if old not in source:raise ValueError('reader_detail_filter_anchor_changed')
        source=source.replace(old,"    where, params = ['c.last_seen>=%s'], [time.time()-HOT_DAYS*86400]",1)
    tree=ast.parse(source);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef));lines=source.splitlines(keepends=True)
    lines[node.lineno-1:node.lineno-1]=["from tier_policy import HOT_DAYS, ONLINE_DAYS, metadata as tier_metadata\nSUMMARY_VIEW_SCOPE='online_current_month_to_latest'\nSUMMARY_VIEW_TIME_BASIS='online_window_start_to_latest_sample_date'\n\n"]
    source=''.join(lines);compile(source,'reader-candidate','exec');return source
