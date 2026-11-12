"""Five-second source-IP rates from consecutive observed counter deltas."""
from collections import deque

RATE_WINDOW_SECONDS = 5
RATE_BASIS = "source_ip_five_second_sampled_payload_rate"


class SourceRates:
    def __init__(self):
        self.previous = {}
        self.tick = None
        self.wall = None
        self.frames = deque()
        self.since = {}
        self.seen = {}

    def update(self, rows, tick, wall):
        # rows: connection id, proven original IP, cumulative up/down, start time.
        current = {r[0]: r for r in rows}
        ips = {r[1] for r in rows if r[1]}
        continuous = self.tick is not None and 0 < tick - self.tick <= RATE_WINDOW_SECONDS
        if not continuous:
            self.frames.clear()
            self.since.clear()
            self.seen.clear()
        totals, invalid = {}, set()
        if continuous:
            for cid, ip, up, down, started in rows:
                previous = self.previous.get(cid)
                if previous and previous[1] != ip:
                    invalid.update(x for x in (previous[1], ip) if x)
                if not ip:
                    continue
                delta = None
                if previous and previous[1] == ip:
                    if up < previous[2] or down < previous[3]:
                        invalid.add(ip)
                    else:
                        delta = (up - previous[2], down - previous[3])
                elif not previous and self.wall <= started <= wall:
                    # First counters are attributable only for a connection born in this interval.
                    delta = (up, down)
                if delta is not None:
                    value = totals.setdefault(ip, [0, 0])
                    value[0] += delta[0]
                    value[1] += delta[1]
            for ip in invalid:
                self.since[ip] = tick
                totals.pop(ip, None)
            self.frames.append((self.tick, tick, totals))
        for ip in ips:
            self.since.setdefault(ip, tick)
            self.seen[ip] = tick
        cutoff = tick - RATE_WINDOW_SECONDS
        while self.frames and self.frames[0][1] <= cutoff:
            self.frames.popleft()
        for ip in list(self.seen):
            if self.seen[ip] < cutoff:
                self.seen.pop(ip, None)
                self.since.pop(ip, None)
        rates = {}
        for ip in ips:
            if tick - self.since[ip] < RATE_WINDOW_SECONDS:
                continue
            up = down = 0.0
            for start, end, values in self.frames:
                # Fractional boundary intervals use linear counter interpolation.
                weight = (end - max(start, cutoff, self.since[ip])) / (end - start)
                if weight > 0:
                    delta = values.get(ip, (0, 0))
                    up += delta[0] * weight
                    down += delta[1] * weight
            rates[ip] = (RATE_WINDOW_SECONDS, up / RATE_WINDOW_SECONDS, down / RATE_WINDOW_SECONDS)
        self.previous, self.tick, self.wall = current, tick, wall
        return {r[0]: rates.get(r[1], (None, None, None)) for r in rows}
