# AutoGen Integration

REVOC governs AutoGen multi-agent conversations by intercepting all LLM calls at the
proxy layer. The governance depth counter automatically tracks nested agent calls.

## Prerequisites

```bash
pip install pyautogen
docker run -d -p 8080:8080 -p 3000:3000 \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  --name revoc ghcr.io/revoc-ai/revoc:beta
```

## Basic Two-Agent Conversation

```python
import autogen

# Point AutoGen's OpenAI config at REVOC
config_list = [
    {
        "model": "gpt-4o-mini",
        "api_key": "sk-your-key-here",
        "base_url": "http://localhost:8080",
    }
]

llm_config = {"config_list": config_list, "timeout": 120}

assistant = autogen.AssistantAgent(
    name="assistant",
    llm_config=llm_config,
    system_message="You are a helpful AI assistant.",
)

user_proxy = autogen.UserProxyAgent(
    name="user_proxy",
    human_input_mode="NEVER",
    max_consecutive_auto_reply=5,
    llm_config=llm_config,
)

# Every turn in the conversation passes through REVOC
# Governance depth increments with each nested LLM call
user_proxy.initiate_chat(
    assistant,
    message="Explain the water cycle in two sentences.",
)
```

## Code Execution Agent with Governance

```python
import autogen

config_list = [
    {
        "model": "gpt-4o-mini",
        "api_key": "sk-your-key-here",
        "base_url": "http://localhost:8080",
    }
]

# AutoGen's code executor agent — REVOC governs the LLM calls that
# generate code, but does not execute the code itself
assistant = autogen.AssistantAgent(
    name="coder",
    llm_config={"config_list": config_list},
    system_message="Write Python code to solve the given problem.",
)

user_proxy = autogen.UserProxyAgent(
    name="executor",
    human_input_mode="NEVER",
    max_consecutive_auto_reply=3,
    code_execution_config={"work_dir": "/tmp/autogen", "use_docker": False},
)

# REVOC blocks if the generated code contains path traversal or SSRF patterns
user_proxy.initiate_chat(
    assistant,
    message="Write code to calculate the sum of integers from 1 to 100.",
)
```

## Group Chat with Governance Depth Tracking

```python
import autogen

config_list = [
    {
        "model": "gpt-4o-mini",
        "api_key": "sk-your-key-here",
        "base_url": "http://localhost:8080",
    }
]

llm_config = {"config_list": config_list}

researcher = autogen.AssistantAgent("researcher", llm_config=llm_config,
    system_message="Research and summarize information.")
analyst = autogen.AssistantAgent("analyst", llm_config=llm_config,
    system_message="Analyze and draw conclusions from research.")
writer = autogen.AssistantAgent("writer", llm_config=llm_config,
    system_message="Write a clear report based on the analysis.")

user_proxy = autogen.UserProxyAgent(
    "manager",
    human_input_mode="NEVER",
    max_consecutive_auto_reply=1,
)

group_chat = autogen.GroupChat(
    agents=[user_proxy, researcher, analyst, writer],
    messages=[],
    max_round=6,
)

manager = autogen.GroupChatManager(
    groupchat=group_chat,
    llm_config=llm_config,
)

# Each agent turn goes through REVOC independently
# The governance depth counter tracks nesting automatically
# If depth reaches 10, REVOC returns 503 REVOC_GOVERNANCE_DEPTH_EXCEEDED
user_proxy.initiate_chat(
    manager,
    message="Analyze the benefits of using a governance proxy for AI applications.",
)
```

## Checking Governance Headers

AutoGen does not expose HTTP response headers by default. To inspect REVOC decisions,
add a custom HTTP hook or use the REVOC dashboard:

```python
import httpx
import autogen

# Custom transport that logs REVOC headers
class RevocLoggingTransport(httpx.BaseTransport):
    def __init__(self, wrapped: httpx.BaseTransport):
        self._wrapped = wrapped

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        response = self._wrapped.handle_request(request)
        decision = response.headers.get("x-revoc-decision", "unknown")
        trace = response.headers.get("x-revoc-dashboard", "")
        if decision != "allow":
            print(f"REVOC [{decision}]: {trace}")
        return response
```
