from __future__ import annotations

from typing import Any

from porygon_responder.executor import DockerResponseExecutor


class FakeContainer:
    def __init__(self, *, running: bool = True, paused: bool = False, protected: bool = False):
        self.id = "a" * 64
        self.running = running
        self.paused = paused
        self.protected = protected
        self.attrs: dict[str, Any] = {}
        self.reload()

    def reload(self) -> None:
        self.attrs = {
            "Id": self.id,
            "Name": "/workload",
            "Config": {
                "Labels": {"com.porygon.protected": "true"} if self.protected else {}
            },
            "HostConfig": {"RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}},
            "State": {
                "Status": "running" if self.running else "exited",
                "Running": self.running,
                "Paused": self.paused,
                "Restarting": False,
                "Dead": False,
                "OOMKilled": False,
                "ExitCode": 0,
            },
        }

    def pause(self) -> None:
        self.paused = True

    def unpause(self) -> None:
        self.paused = False
        self.running = True

    def stop(self, *, timeout: int) -> None:
        assert timeout == 10
        self.running = False
        self.paused = False

    def start(self) -> None:
        self.running = True
        self.paused = False


class Containers:
    def __init__(self, container: FakeContainer):
        self.container = container

    def get(self, container_id: str) -> FakeContainer:
        return self.container


class Client:
    def __init__(self, container: FakeContainer):
        self.containers = Containers(container)


def executor(container: FakeContainer) -> DockerResponseExecutor:
    return DockerResponseExecutor(
        base_url="unused",
        timeout_seconds=10,
        stop_timeout_seconds=10,
        protected_label="com.porygon.protected",
        client=Client(container),
    )


def test_pause_and_rollback_are_verified() -> None:
    container = FakeContainer()
    execute = executor(container).execute(
        action_type="pause_container", target_container_id=container.id, operation="execute"
    )
    assert execute.success is True
    assert execute.post_state["paused"] is True

    rollback = executor(container).execute(
        action_type="pause_container", target_container_id=container.id, operation="rollback"
    )
    assert rollback.success is True
    assert rollback.post_state["paused"] is False
    assert rollback.post_state["running"] is True


def test_stop_and_start_are_idempotent_but_not_claimed_as_full_state_restore() -> None:
    container = FakeContainer()
    execute = executor(container).execute(
        action_type="stop_container", target_container_id=container.id, operation="execute"
    )
    assert execute.success is True
    assert execute.post_state["running"] is False

    repeated = executor(container).execute(
        action_type="stop_container", target_container_id=container.id, operation="execute"
    )
    assert repeated.success is True
    assert repeated.result["changed"] is False

    rollback = executor(container).execute(
        action_type="stop_container", target_container_id=container.id, operation="rollback"
    )
    assert rollback.success is True
    assert rollback.post_state["running"] is True


def test_protected_container_is_refused() -> None:
    container = FakeContainer(protected=True)
    result = executor(container).execute(
        action_type="pause_container", target_container_id=container.id, operation="execute"
    )
    assert result.success is False
    assert result.error_code == "protected_target"
    assert result.pre_state["container_id"] == container.id


def test_exact_full_container_id_is_required() -> None:
    container = FakeContainer()
    result = executor(container).execute(
        action_type="pause_container", target_container_id="a" * 12, operation="execute"
    )
    assert result.success is False
    assert result.error_code == "invalid_request"
