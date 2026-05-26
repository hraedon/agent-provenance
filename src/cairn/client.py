"""High-level SDK for Cairn provenance logging.

Provides :class:`CairnClient`, the recommended entry point for Python
applications that want to log agent tool calls to substrate.

Usage::

    from cairn.client import CairnClient

    with CairnClient(dsn="postgresql://...", project="cairn", key_path="/keys.json") as cairn:
        # Record scope attestation
        cairn.attest_scope(harnesses=[{"name": "my-agent", "version": "1.0"}])

        # Log a tool call (context manager handles begin/end)
        with cairn.tool_call("Edit", args={"filePath": "/tmp/foo.py"}, files=["/tmp/foo.py"]) as tc:
            # ... perform the actual edit ...
            tc.set_result(exit_code=0)

        # Or manual begin/end
        tc = cairn.begin("Bash", args={"command": "ls"}, files=[])
        # ... run the command ...
        cairn.end(tc, exit_code=0, stdout="file1.py\\nfile2.py")
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .adapter import CairnAdapter
from .schema import CairnConfig


class ToolCallContext:
    """Tracks an in-progress tool call for use as a context manager.

    Returned by :meth:`CairnClient.tool_call` and :meth:`CairnClient.begin`.
    """

    def __init__(
        self,
        client: CairnClient,
        work_item_id: uuid.UUID,
        tool: str,
        files: list[str],
    ) -> None:
        self._client = client
        self.work_item_id = work_item_id
        self.tool = tool
        self.files = files
        self._result_summary: dict[str, Any] | None = None
        self._error: str | None = None
        self._ended = False

    def set_result(
        self,
        *,
        exit_code: int = 0,
        stdout: str | None = None,
        stderr: str | None = None,
    ) -> None:
        """Set the result summary (called before __exit__)."""
        self._result_summary = {
            "exit_code": exit_code,
        }
        if stdout is not None:
            self._result_summary["stdout"] = stdout
        if stderr is not None:
            self._result_summary["stderr"] = stderr

    def set_error(self, error: str) -> None:
        """Mark the tool call as failed."""
        self._error = error

    def end(self) -> Any:
        """Explicitly end this tool call (optional if using context manager)."""
        if self._ended:
            return None
        self._ended = True
        return self._client._adapter.end_tool_call(
            self.work_item_id,
            result_summary=self._result_summary,
            files=self.files,
            error=self._error,
        )

    def __enter__(self) -> ToolCallContext:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if exc_type is not None and self._error is None:
            self.set_error(str(exc_val)[:500])
        self.end()


class CairnClient:
    """High-level client for Cairn provenance logging.

    Handles substrate connection lifecycle, session management, and
    provides a clean API for logging agent tool calls.

    Args:
        dsn: Postgres DSN for substrate.
        project: Substrate project name.
        key_path: Path to HMAC key file.
        harness_name: Name of the agent harness (e.g. ``"opencode"``).
        harness_version: Version of the agent harness.
        principal_id: Human principal identifier.  Defaults to OS user.
        session_id: Session identifier for grouping events.  Defaults
            to a random UUID.
        config_digest: SHA-256 of the harness configuration file.
        actor_id: Actor identifier for substrate events.
        actor_kind: Actor kind (``"agent"``, ``"human"``, ``"system"``).
        workflow_name: Substrate workflow name.

    Example::

        with CairnClient(
            dsn="postgresql://localhost/cairn",
            project="my-project",
            key_path="/keys/cairn.json",
            harness_name="my-agent",
            harness_version="1.0.0",
        ) as cairn:
            cairn.attest_scope(harnesses=[{"name": "my-agent", "version": "1.0.0"}])

            with cairn.tool_call("Edit", args=edit_args, files=[path]) as tc:
                do_edit()
                tc.set_result(exit_code=0)
    """

    def __init__(
        self,
        dsn: str,
        project: str,
        key_path: str | Path,
        *,
        harness_name: str = "unknown",
        harness_version: str = "unknown",
        principal_id: str | None = None,
        session_id: str | None = None,
        config_digest: str | None = None,
        actor_id: str | None = None,
        actor_kind: str = "agent",
        workflow_name: str = "cairn_agent_actions",
    ) -> None:
        self._dsn = str(dsn)
        self._project = project
        self._key_path = str(key_path)
        self._harness_name = harness_name
        self._harness_version = harness_version
        self._session_id = session_id or str(uuid.uuid4())
        self._principal_id = principal_id or self._detect_principal()
        self._closed = False

        # Lazy-initialized
        self._substrate: Any = None
        self._adapter: CairnAdapter | None = None
        self._config = CairnConfig(
            harness_name=harness_name,
            harness_version=harness_version,
            config_digest=config_digest,
        )
        self._actor_id = actor_id
        self._actor_kind = actor_kind
        self._workflow_name = workflow_name

    @staticmethod
    def _detect_principal() -> str:
        """Detect principal_id from the environment."""
        env_id = os.environ.get("PRINCIPAL_ID")
        if env_id:
            return env_id
        try:
            return f"human:{os.getlogin()}"
        except OSError:
            import getpass

            return f"human:{getpass.getuser()}"

    def _ensure_connected(self) -> CairnAdapter:
        """Lazily connect to substrate and create the adapter."""
        if self._adapter is not None:
            return self._adapter

        from substrate import Substrate

        self._substrate = Substrate(
            dsn=self._dsn,
            project=self._project,
            hmac_key_path=self._key_path,
        )
        self._adapter = CairnAdapter(
            self._substrate,
            config=self._config,
            on_behalf_of={
                "principal_id": self._principal_id,
                "session_id": self._session_id,
            },
            actor_id=self._actor_id,
            actor_kind=self._actor_kind,
            workflow_name=self._workflow_name,
        )
        return self._adapter

    @property
    def session_id(self) -> str:
        """The session ID for this client instance."""
        return self._session_id

    @property
    def principal_id(self) -> str:
        """The principal ID for this client instance."""
        return self._principal_id

    # ------------------------------------------------------------------
    # Scope attestation
    # ------------------------------------------------------------------

    def attest_scope(
        self,
        harnesses: list[dict[str, Any]] | None = None,
        scope_statement: str | None = None,
        harness_config_digests: dict[str, str] | None = None,
    ) -> Any:
        """Record a scope attestation event.

        Args:
            harnesses: List of harness dicts with ``name`` and ``version``.
                Defaults to the client's own harness.
            scope_statement: Human-readable scope statement.  Defaults to
                ``"In scope: {harness_name}."``.
            harness_config_digests: Map of harness name to config digest.

        Returns:
            The substrate event recording the attestation.
        """
        adapter = self._ensure_connected()
        if harnesses is None:
            harnesses = [
                {"name": self._harness_name, "version": self._harness_version}
            ]
        if scope_statement is None:
            scope_statement = f"In scope: {self._harness_name}."
        return adapter.attest_scope(
            principal_id=self._principal_id,
            harnesses=harnesses,
            scope_statement=scope_statement,
            harness_config_digests=harness_config_digests,
        )

    # ------------------------------------------------------------------
    # Tool call logging
    # ------------------------------------------------------------------

    def begin(
        self,
        tool: str,
        *,
        args: dict[str, Any] | None = None,
        files: list[str] | None = None,
    ) -> ToolCallContext:
        """Begin logging a tool call.

        Args:
            tool: Tool name (``Edit``, ``Write``, ``Read``, ``Bash``, ...).
            args: Tool arguments (will be hashed, not stored).
            files: Files touched by this tool call.

        Returns:
            A :class:`ToolCallContext` to pass to :meth:`end`.
        """
        adapter = self._ensure_connected()
        wi = adapter.begin_tool_call(
            tool=tool,
            tool_args=args or {},
            files=files,
        )
        return ToolCallContext(
            client=self,
            work_item_id=wi.work_item_id,
            tool=tool,
            files=files or [],
        )

    def end(
        self,
        tc: ToolCallContext,
        *,
        exit_code: int = 0,
        stdout: str | None = None,
        stderr: str | None = None,
        error: str | None = None,
    ) -> Any:
        """End a tool call.

        Args:
            tc: The :class:`ToolCallContext` from :meth:`begin`.
            exit_code: Process exit code.
            stdout: Standard output (will be hashed).
            stderr: Standard error (will be hashed).
            error: Error message (marks the call as failed).

        Returns:
            The substrate event recording the completion.
        """
        if error:
            tc.set_error(error)
        else:
            tc.set_result(exit_code=exit_code, stdout=stdout, stderr=stderr)
        return tc.end()

    @contextmanager
    def tool_call(
        self,
        tool: str,
        *,
        args: dict[str, Any] | None = None,
        files: list[str] | None = None,
    ) -> Generator[ToolCallContext, None, None]:
        """Context manager for a tool call.

        Automatically calls :meth:`begin` on entry and :meth:`end` on exit.
        If an exception is raised, the tool call is recorded as failed.

        Args:
            tool: Tool name.
            args: Tool arguments.
            files: Files touched.

        Yields:
            A :class:`ToolCallContext` for setting results.

        Example::

            with cairn.tool_call("Edit", args=edit_args, files=[path]) as tc:
                do_edit()
                tc.set_result(exit_code=0)
        """
        tc = self.begin(tool, args=args, files=files)
        try:
            yield tc
        except BaseException as exc:
            tc.set_error(str(exc)[:500])
            raise
        finally:
            tc.end()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the substrate connection."""
        if self._closed:
            return
        self._closed = True
        if self._substrate is not None:
            self._substrate.close()
            self._substrate = None
            self._adapter = None

    def __enter__(self) -> CairnClient:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()
