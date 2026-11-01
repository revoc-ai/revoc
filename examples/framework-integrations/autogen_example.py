"""
REVOC + AutoGen integration example — complete, runnable.

Before running:
    pip install pyautogen
    docker run -d -p 8080:8080 -p 3000:3000 \
      -e OPENAI_API_KEY=$OPENAI_API_KEY \
      --name revoc ghcr.io/revoc-ai/revoc:beta
"""

import os
import autogen

REVOC_BASE_URL = os.getenv("REVOC_BASE_URL", "http://localhost:8080")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "sk-mock")

# AutoGen config list — all calls routed through REVOC
CONFIG_LIST = [
    {
        "model": "gpt-4o-mini",
        "api_key": OPENAI_API_KEY,
        "base_url": REVOC_BASE_URL,
    }
]

LLM_CONFIG = {"config_list": CONFIG_LIST, "timeout": 60, "cache_seed": None}


def demo_two_agent_conversation() -> None:
    """Two agents exchange messages — every LLM call passes through REVOC."""
    print("\n--- Two-agent conversation ---")

    assistant = autogen.AssistantAgent(
        name="assistant",
        llm_config=LLM_CONFIG,
        system_message="Answer questions concisely in one or two sentences.",
    )

    user_proxy = autogen.UserProxyAgent(
        name="user",
        human_input_mode="NEVER",
        max_consecutive_auto_reply=1,
        is_termination_msg=lambda x: "TERMINATE" in x.get("content", ""),
    )

    user_proxy.initiate_chat(
        assistant,
        message="What is the main benefit of using a governance proxy for AI? Reply then say TERMINATE.",
    )


def demo_depth_tracking() -> None:
    """
    Demonstrates governance depth tracking in nested agent calls.

    Each turn in the AutoGen conversation increments the X-Revoc-Depth counter
    on the outgoing upstream request. REVOC enforces a maximum depth of 10.
    """
    print("\n--- Depth tracking (nested agent calls) ---")
    print("  Each AutoGen conversation turn increments X-Revoc-Depth on the upstream request.")
    print("  REVOC blocks with REVOC_GOVERNANCE_DEPTH_EXCEEDED if depth reaches 10.")
    print("  This prevents infinite agent recursion loops.")

    # A single-turn conversation stays at depth 1
    assistant = autogen.AssistantAgent(
        name="depth_demo",
        llm_config=LLM_CONFIG,
        system_message="Reply with a single word: OK. Then say TERMINATE.",
    )
    user_proxy = autogen.UserProxyAgent(
        name="driver",
        human_input_mode="NEVER",
        max_consecutive_auto_reply=1,
        is_termination_msg=lambda x: "TERMINATE" in x.get("content", ""),
    )
    user_proxy.initiate_chat(assistant, message="Say OK then TERMINATE.")


if __name__ == "__main__":
    print("REVOC + AutoGen Example")
    print(f"Proxy: {REVOC_BASE_URL}")
    print(f"Dashboard: http://localhost:3000")

    demo_two_agent_conversation()
    demo_depth_tracking()

    print("\nDone. View traces at http://localhost:3000")
