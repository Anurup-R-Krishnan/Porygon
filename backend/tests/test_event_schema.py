from __future__ import annotations

from porygon_api.schemas import RuntimeEventBatchIn


def test_runtime_event_schema_accepts_normalized_event() -> None:
    payload = RuntimeEventBatchIn.model_validate(
        {
            "events": [
                {
                    "event_id": "a" * 64,
                    "docker_host_id": "daemon-1",
                    "event_type": "container",
                    "action": "start",
                    "scope": "local",
                    "actor_id": "container-1",
                    "occurred_at": "2026-07-21T10:00:00+00:00",
                    "time_nano": 1784628000000000000,
                    "container_id": "container-1",
                    "container_name": "probe",
                    "image_id": "sha256:image",
                    "image_ref": "alpine:3.20",
                    "image_digest": "alpine@sha256:" + "b" * 64,
                    "image_digest_status": "resolved",
                    "command": "sleep 300",
                    "container_user": "1000",
                    "attributes": {},
                    "container_snapshot": {},
                    "raw_event": {"Type": "container", "Action": "start"},
                }
            ]
        }
    )
    assert payload.events[0].action == "start"
