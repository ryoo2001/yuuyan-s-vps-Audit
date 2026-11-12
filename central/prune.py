#!/usr/bin/env python3
"""Independent retention even while the publisher is offline."""
import os
from receive import LOCK_NAME, connect, prune
if __name__=='__main__':
    db=connect()
    locks=tuple(x for x in os.environ.get('TRAFFIC_CENTRAL_LOCKS', LOCK_NAME).split(',') if x)
    held=[]
    try:
        with db.cursor() as c:
            for lock in locks:
                c.execute('SELECT GET_LOCK(%s,0)', (lock,))
                if c.fetchone()[0] != 1:
                    for held_lock in held:
                        c.execute('SELECT RELEASE_LOCK(%s)', (held_lock,))
                    print('prune_skipped=receiver_busy')
                    raise SystemExit(0)
                held.append(lock)
        # Bounded per pass; repeated each five minutes, no whole-database locks.
        deleted=prune(db)
        print('pruned_rows='+str(deleted))
    finally:
        if held:
            with db.cursor() as c:
                for lock in held:
                    c.execute('SELECT RELEASE_LOCK(%s)', (lock,))
        db.close()
