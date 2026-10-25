from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from porygon_api.main import _reconcile_process_identities
from porygon_api.models import ContainerIdentity, ProcessExecEvent
from test_parent_correlation import _event


def identity(host='host-1', suffix='a'):
    now=datetime.now(timezone.utc)
    return ContainerIdentity(docker_host_id=host,container_id='abcdef123456'+suffix*52,
        container_name='ephemeral',image_id='sha256:image',image_ref='example/app:latest',
        image_digest='example/app@sha256:'+'a'*64,image_digest_status='resolved',
        current_snapshot={},first_seen_at=now,last_seen_at=now)


def test_late_lifecycle_identity_repairs_committed_process_events():
    engine=create_engine('sqlite+pysqlite:///:memory:')
    ContainerIdentity.__table__.create(engine);ProcessExecEvent.__table__.create(engine)
    with Session(engine) as db:
        event=_event('c'*64,datetime.now(timezone.utc),321)
        event.reported_container_id='abcdef123456';event.container_id=None
        event.image_digest=None;event.correlation_status='unresolved'
        db.add(event);db.commit()
        assert _reconcile_process_identities(db)==0
        db.add(identity());db.commit()
        assert _reconcile_process_identities(db)==1
        db.refresh(event)
        assert event.container_id=='abcdef123456'+'a'*52
        assert event.image_digest=='example/app@sha256:'+'a'*64
        assert event.correlation_status=='resolved'
        assert _reconcile_process_identities(db)==0


def test_ambiguous_prefix_is_not_assigned_to_an_arbitrary_container():
    engine=create_engine('sqlite+pysqlite:///:memory:')
    ContainerIdentity.__table__.create(engine);ProcessExecEvent.__table__.create(engine)
    with Session(engine) as db:
        event=_event('d'*64,datetime.now(timezone.utc),123)
        event.reported_container_id='abcdef123456';event.reported_docker_host_id=None
        event.image_digest=None;event.container_id=None;event.correlation_status='unresolved'
        db.add_all([event,identity(),identity('host-2')]);db.commit()
        assert _reconcile_process_identities(db)==0
        assert event.container_id is None
        event.reported_docker_host_id='host-2';db.commit()
        assert _reconcile_process_identities(db)==1
        assert event.docker_host_id=='host-2'
