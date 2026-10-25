import json
import time
from datetime import datetime, timezone

from porygon_telemetry.config import Settings
from porygon_telemetry.file_source import FalcoFileSource
from porygon_telemetry.spool import TelemetryStore
from porygon_telemetry.state import TelemetryState
from test_normalizer import _raw_event


def test_reader_batches_complete_lines_and_preserves_partial_tail(tmp_path):
    path=tmp_path/'events.jsonl'
    raw=_raw_event()
    payload=json.dumps(raw).encode()
    path.write_bytes(payload+b'\n'+payload[:30])
    store=TelemetryStore(str(tmp_path/'spool.db'),max_events=100)
    settings=Settings(internal_api_token='x'*32,falco_log_path=str(path),falco_poll_seconds=.05)
    state=TelemetryState(started_at=datetime.now(timezone.utc))
    source=FalcoFileSource(settings,state,store);source.start()
    try:
        deadline=time.monotonic()+3
        while store.get_file_cursor()[1]<len(payload)+1 and time.monotonic()<deadline:time.sleep(.01)
        assert store.count()==1
        assert store.get_file_cursor()[1]==len(payload)+1
        with path.open('ab') as stream:stream.write(payload[30:]+b'\n')
        deadline=time.monotonic()+3
        while store.get_file_cursor()[1]<2*(len(payload)+1) and time.monotonic()<deadline:time.sleep(.01)
        assert store.get_file_cursor()[1]==2*(len(payload)+1)
        assert store.count()==1
        assert state.duplicates_ignored==1
    finally:source.stop()


def test_rotation_preserves_unread_and_late_appended_bytes(tmp_path):
    import os
    active=tmp_path/'events.jsonl';draining=tmp_path/'events.jsonl.draining'
    active.write_bytes(b'x'*1_048_576)
    store=TelemetryStore(str(tmp_path/'spool.db'),max_events=100)
    source=FalcoFileSource(Settings(internal_api_token='x'*32,falco_log_path=str(active),falco_rotate_bytes=1_048_576),
                           TelemetryState(started_at=datetime.now(timezone.utc)),store)
    inode=active.stat().st_ino
    store.update_file_cursor(inode,100)
    source._rotate_consumed_file(active,draining,active)
    assert not draining.exists()
    store.update_file_cursor(inode,active.stat().st_size)
    source._rotate_consumed_file(active,draining,active)
    assert draining.stat().st_ino==inode and active.exists()
    with draining.open('ab') as f:f.write(b'late-write\n')
    os.utime(draining,(time.time()-5,time.time()-5))
    source._rotate_consumed_file(active,draining,draining)
    assert draining.exists()
    store.update_file_cursor(inode,draining.stat().st_size)
    source._rotate_consumed_file(active,draining,draining)
    assert not draining.exists()
