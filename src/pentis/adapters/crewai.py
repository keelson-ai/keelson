"""CrewAI native adapter — wraps crew.kickoff() directly (not HTTP)."""

from __future__ import annotations

import time
from typing import Any, cast

from pentis.adapters.base import BaseAdapter


class CrewAIAdapter(BaseAdapter):
    """Adapter that sends attack prompts to a CrewAI crew/agent directly.

    Requires `crewai` to be installed: `pip install pentis[crewai]`

    Usage:
        from crewai import Agent, Task, Crew
        agent = Agent(role="assistant", goal="help users", backstory="...")
        adapter = CrewAIAdapter(agent=agent)
        # or
        crew = Crew(agents=[agent], tasks=[...])
        adapter = CrewAIAdapter(crew=crew)
    """

    def __init__(
        self,
        agent: Any | None = None,
        crew: Any | None = None,
        task_description: str = "Respond to the following user message",
    ):
        if agent is None and crew is None:
            raise ValueError("Either 'agent' or 'crew' must be provided")
        self._agent = agent
        self._crew = crew
        self._task_description = task_description

    async def _send_messages_impl(
        self,
        messages: list[dict[str, str]],
        model: str = "default",
        max_response_tokens: int | None = None,  # noqa: ARG002
    ) -> tuple[str, int]:
        """Send messages by running the CrewAI agent/crew."""
        user_message = self._last_user_message(messages)

        start = time.monotonic()

        if self._crew is not None:
            response = await self._run_crew(user_message)
        else:
            response = await self._run_agent(user_message)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        return response, elapsed_ms

    async def _run_crew(self, user_input: str) -> str:
        """Run a CrewAI crew with the given input."""
        assert self._crew is not None
        result: Any = self._crew.kickoff(inputs={"input": user_input})
        # CrewOutput has a .raw attribute or can be cast to string
        if hasattr(result, "raw"):
            return str(result.raw)
        return str(result)

    async def _run_agent(self, user_input: str) -> str:
        """Run a single CrewAI agent with a task."""
        from crewai import Crew, Task  # type: ignore[import-untyped]

        task = cast(
            Any,
            Task(
                description=f"{self._task_description}: {user_input}",
                expected_output="A response to the user's message",
                agent=self._agent,
            ),
        )
        crew = cast(Any, Crew(agents=[self._agent], tasks=[task], verbose=False))
        result: Any = crew.kickoff()
        if hasattr(result, "raw"):
            return str(result.raw)
        return str(result)

    async def health_check(self) -> bool:
        """Check if the CrewAI agent/crew is available."""
        return self._agent is not None or self._crew is not None

    async def close(self) -> None:
        """No resources to clean up for in-process adapter."""
        pass
