from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import docker
from docker.errors import APIError, DockerException, NotFound


class ContainerLike(Protocol):
    id: str
    attrs: dict[str, Any]

    def reload(self) -> None: ...
    def pause(self) -> None: ...
    def unpause(self) -> None: ...
    def stop(self, *, timeout: int) -> None: ...
    def start(self) -> None: ...


@dataclass(frozen=True)
class ActionResult:
    success: bool
    pre_state: dict[str, Any]
    post_state: dict[str, Any]
    result: dict[str, Any]
    error_code: str | None = None
    error_message: str | None = None


class DockerResponseExecutor:
    def __init__(
        self,
        *,
        base_url: str,
        timeout_seconds: int,
        stop_timeout_seconds: int,
        protected_label: str,
        client: Any | None = None,
    ) -> None:
        self.client = client or docker.DockerClient(base_url=base_url, timeout=timeout_seconds)
        self.stop_timeout_seconds = stop_timeout_seconds
        self.protected_label = protected_label

    @staticmethod
    def _state(container: ContainerLike) -> dict[str, Any]:
        state = dict(container.attrs.get("State") or {})
        config = dict(container.attrs.get("Config") or {})
        labels = dict(config.get("Labels") or {})
        host_config = dict(container.attrs.get("HostConfig") or {})
        restart_policy = dict(host_config.get("RestartPolicy") or {})
        return {
            "container_id": container.id,
            "name": str(container.attrs.get("Name") or "").lstrip("/") or None,
            "status": state.get("Status"),
            "running": bool(state.get("Running")),
            "paused": bool(state.get("Paused")),
            "restarting": bool(state.get("Restarting")),
            "dead": bool(state.get("Dead")),
            "oom_killed": bool(state.get("OOMKilled")),
            "exit_code": state.get("ExitCode"),
            "restart_policy": restart_policy,
            "labels": labels,
        }

    def _exact_container(self, container_id: str) -> ContainerLike:
        container = self.client.containers.get(container_id)
        container.reload()
        if container.id != container_id:
            raise ValueError("target_container_id must be the exact full Docker container ID")
        return container

    def _guard(self, state: dict[str, Any]) -> None:
        labels = dict(state.get("labels") or {})
        value = str(labels.get(self.protected_label, "")).lower()
        if value in {"1", "true", "yes"}:
            raise PermissionError("target container is protected by Porygon policy")

    def execute(
        self,
        *,
        action_type: str,
        target_container_id: str | None,
        operation: str,
    ) -> ActionResult:
        if action_type == "observe_only":
            return ActionResult(
                success=True,
                pre_state={},
                post_state={},
                result={"operation": operation, "changed": False, "verification": "no-op"},
            )
        if target_container_id is None:
            return ActionResult(
                success=False,
                pre_state={},
                post_state={},
                result={},
                error_code="missing_target",
                error_message="Docker response action requires an exact container ID",
            )

        pre_state: dict[str, Any] = {}
        post_state: dict[str, Any] = {}
        try:
            container = self._exact_container(target_container_id)
            pre_state = self._state(container)
            self._guard(pre_state)

            if operation == "execute":
                changed = self._apply(container, action_type, pre_state)
            elif operation == "rollback":
                changed = self._rollback(container, action_type, pre_state)
            else:
                raise ValueError(f"unsupported operation: {operation}")

            container.reload()
            post_state = self._state(container)
            self._verify(action_type, operation, post_state)
            return ActionResult(
                success=True,
                pre_state=pre_state,
                post_state=post_state,
                result={
                    "operation": operation,
                    "action_type": action_type,
                    "changed": changed,
                    "verification": "passed",
                    "verification_scope": "immediate Docker inspect state",
                },
            )
        except NotFound as exc:
            return self._failure("container_not_found", exc, pre_state, post_state)
        except PermissionError as exc:
            return self._failure("protected_target", exc, pre_state, post_state)
        except ValueError as exc:
            return self._failure("invalid_request", exc, pre_state, post_state)
        except APIError as exc:
            return self._failure("docker_api_error", exc, pre_state, post_state)
        except DockerException as exc:
            return self._failure("docker_unavailable", exc, pre_state, post_state)

    def _apply(
        self,
        container: ContainerLike,
        action_type: str,
        state: dict[str, Any],
    ) -> bool:
        if action_type == "pause_container":
            if state["paused"]:
                return False
            if not state["running"]:
                raise ValueError("container must be running before it can be paused")
            container.pause()
            return True
        if action_type == "stop_container":
            if not state["running"]:
                return False
            container.stop(timeout=self.stop_timeout_seconds)
            return True
        raise ValueError(f"unsupported action_type: {action_type}")

    def _rollback(
        self,
        container: ContainerLike,
        action_type: str,
        state: dict[str, Any],
    ) -> bool:
        if action_type == "pause_container":
            if not state["paused"]:
                return False
            container.unpause()
            return True
        if action_type == "stop_container":
            if state["running"]:
                return False
            container.start()
            return True
        raise ValueError(f"unsupported rollback action_type: {action_type}")

    @staticmethod
    def _verify(action_type: str, operation: str, state: dict[str, Any]) -> None:
        if action_type == "pause_container":
            expected = operation == "execute"
            if bool(state["paused"]) is not expected:
                raise APIError("post-action pause state did not match the requested operation")
            if operation == "rollback" and not state["running"]:
                raise APIError("container did not return to a running state after unpause")
        elif action_type == "stop_container":
            expected_running = operation == "rollback"
            if bool(state["running"]) is not expected_running:
                raise APIError("post-action running state did not match the requested operation")

    @staticmethod
    def _failure(
        code: str,
        exc: Exception,
        pre_state: dict[str, Any],
        post_state: dict[str, Any],
    ) -> ActionResult:
        return ActionResult(
            success=False,
            pre_state=pre_state,
            post_state=post_state,
            result={"verification": "failed"},
            error_code=code,
            error_message=f"{exc.__class__.__name__}: {exc}",
        )
