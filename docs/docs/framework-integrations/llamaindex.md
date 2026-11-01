# LlamaIndex Integration

REVOC governs LlamaIndex applications by intercepting all OpenAI calls at the proxy layer.

## Prerequisites

```bash
pip install llama-index llama-index-llms-openai llama-index-embeddings-openai
docker run -d -p 8080:8080 -p 3000:3000 \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  --name revoc ghcr.io/revoc-ai/revoc:beta
```

## Basic Query Engine

```python
from llama_index.llms.openai import OpenAI
from llama_index.embeddings.openai import OpenAIEmbedding
from llama_index.core import Settings, VectorStoreIndex, Document

# Route all LlamaIndex LLM calls through REVOC
Settings.llm = OpenAI(
    model="gpt-4o-mini",
    api_base="http://localhost:8080",
    api_key="sk-your-key-here",
)

Settings.embed_model = OpenAIEmbedding(
    api_base="http://localhost:8080",
    api_key="sk-your-key-here",
)

documents = [
    Document(text="REVOC is a governance proxy for AI applications."),
    Document(text="It detects PII, secrets, and prompt injections."),
]

index = VectorStoreIndex.from_documents(documents)
query_engine = index.as_query_engine()

# Every LLM call and embedding call passes through REVOC governance
response = query_engine.query("What does REVOC detect?")
print(response)
```

## ReAct Agent with Tool Governance

```python
from llama_index.llms.openai import OpenAI
from llama_index.core.agent import ReActAgent
from llama_index.core.tools import FunctionTool
from llama_index.core import Settings

Settings.llm = OpenAI(
    model="gpt-4o-mini",
    api_base="http://localhost:8080",
    api_key="sk-your-key-here",
)

def execute_sql(query: str) -> str:
    """Execute a SQL query against the analytics database."""
    # REVOC inspects the query argument before this function is invoked
    # DROP TABLE, DELETE without WHERE, etc. are blocked
    return f"Query result: 42 rows"

sql_tool = FunctionTool.from_defaults(
    fn=execute_sql,
    name="execute_sql",
    description="Execute a SQL SELECT query against the analytics database.",
)

agent = ReActAgent.from_tools([sql_tool], verbose=True)

# Safe query — passes through
response = agent.chat("How many users signed up last week?")
print(response)

# Dangerous query — sec_ddl_mutation_v1 fires, tool call is blocked
# response = agent.chat("Drop the users table")
# → GovernanceError: REVOC_GOVERNANCE_BLOCK (sec_ddl_mutation_v1)
```

## Streaming Response

```python
from llama_index.llms.openai import OpenAI
from llama_index.core import Settings

Settings.llm = OpenAI(
    model="gpt-4o-mini",
    api_base="http://localhost:8080",
    api_key="sk-your-key-here",
)

# REVOC governs streaming responses as they stream
# PII found in mid-stream is redacted before reaching your application
response = Settings.llm.stream_complete("Tell me a story about a user named John Smith.")
for chunk in response:
    print(chunk.delta, end="", flush=True)
# "John Smith" in the response will be masked to [PERSON_NAME] if pii rules apply
```

## Environment Variable Configuration

```bash
export OPENAI_API_BASE=http://localhost:8080
export OPENAI_API_KEY=sk-your-key-here
# LlamaIndex reads OPENAI_API_BASE for the api_base parameter
```
