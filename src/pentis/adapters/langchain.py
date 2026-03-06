"""LangChain native adapter — wraps agent.invoke() directly (not HTTP)."""

from __future__ import annotations

import time
from typing import Any, cast

from pentis.adapters.base import BaseAdapter


class LangChainAdapter(BaseAdapter):
    """Adapter that sends attack prompts to a LangChain agent/chain directly.

    Requires `langchain-core` to be installed: `pip install pentis[langchain]`

    Usage:
        from langchain.agents import AgentExecutor
        agent = AgentExecutor(agent=..., tools=[...])
        adapter = LangChainAdapter(agent=agent)

        # Or with a simple chain/runnable
        from langchain_core.runnables import RunnableSequence
        chain = prompt | llm | parser
        adapter = LangChainAdapter(runnable=chain)
    """

    def __init__(
        self,
        agent: Any | None = None,
        runnable: Any | None = None,
        input_key: str = "input",
        output_key: str = "output",
    ):
        if agent is None and runnable is None:
            raise ValueError("Either 'agent' or 'runnable' must be provided")
        self._agent = agent
        self._runnable = runnable
        self._input_key = input_key
        self._output_key = output_key

    async def _send_messages_impl(
        self,
        messages: list[dict[str, str]],
        model: str = "default",
        max_response_tokens: int | None = None,  # noqa: ARG002
    ) -> tuple[str, int]:
        """Send messages by invoking the LangChain agent/runnable."""
        user_message = self._last_user_message(messages)

        start = time.monotonic()

        target: Any = self._agent or self._runnable
        assert target is not None, "Either 'agent' or 'runnable' must be provided"
        # Try async invoke first, fall back to sync
        if hasattr(target, "ainvoke"):
            result: Any = await target.ainvoke({self._input_key: user_message})
        else:
            result = target.invoke({self._input_key: user_message})

        elapsed_ms = int((time.monotonic() - start) * 1000)

        # Extract output from result
        if isinstance(result, dict):
            result_dict = cast(dict[str, Any], result)
            response = str(result_dict.get(self._output_key, result))
        elif isinstance(result, str):
            response = result
        else:
            # BaseMessage or other LangChain output type
            response = str(getattr(result, "content", result))

        return response, elapsed_ms

    async def health_check(self) -> bool:
        """Check if the LangChain agent/runnable is available."""
        return self._agent is not None or self._runnable is not None

    async def close(self) -> None:
        """No resources to clean up for in-process adapter."""
        pass
