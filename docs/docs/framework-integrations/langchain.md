# LangChain Integration

REVOC governs LangChain applications with zero code changes beyond pointing the OpenAI
client at the REVOC proxy.

## Prerequisites

```bash
pip install langchain langchain-openai openai
docker run -d -p 8080:8080 -p 3000:3000 \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  --name revoc ghcr.io/revoc-ai/revoc:beta
```

## Basic Chain

```python
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage

# Point LangChain's OpenAI client at REVOC
llm = ChatOpenAI(
    model="gpt-4o-mini",
    openai_api_base="http://localhost:8080",
    openai_api_key="sk-your-key-here",
)

response = llm.invoke([HumanMessage(content="Summarize the water cycle in one sentence.")])
print(response.content)
# All governance rules apply. X-Revoc-Decision header is set on every response.
```

## RAG Pipeline

```python
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough

# Both the chat model and embeddings go through REVOC
llm = ChatOpenAI(
    model="gpt-4o-mini",
    openai_api_base="http://localhost:8080",
    openai_api_key="sk-your-key-here",
)

embeddings = OpenAIEmbeddings(
    openai_api_base="http://localhost:8080",
    openai_api_key="sk-your-key-here",
)

prompt = ChatPromptTemplate.from_template(
    "Answer the question based only on this context:\n{context}\n\nQuestion: {question}"
)

# REVOC governs every embedding call and every completion call
chain = (
    {"context": RunnablePassthrough(), "question": RunnablePassthrough()}
    | prompt
    | llm
    | StrOutputParser()
)

result = chain.invoke({"context": "REVOC is a governance proxy.", "question": "What is REVOC?"})
print(result)
```

## Tool Use (Function Calling)

When LangChain uses tool calls, REVOC inspects the accumulated `tool_calls` before
the results are forwarded to any MCP server or tool executor:

```python
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool

@tool
def get_customer_data(customer_id: str) -> str:
    """Retrieve customer account information."""
    # This function is never called if the tool call is blocked by REVOC
    return f"Customer {customer_id}: balance $1234.56"

llm = ChatOpenAI(
    model="gpt-4o-mini",
    openai_api_base="http://localhost:8080",
    openai_api_key="sk-your-key-here",
).bind_tools([get_customer_data])

# If the model tries to call get_customer_data with a SQL injection argument,
# REVOC blocks the tool call before LangChain executes it
response = llm.invoke("Get data for customer robert'); DROP TABLE customers; --")
print(response)
```

## Environment Variable Configuration

For zero-code-change deployment:

```bash
export OPENAI_BASE_URL=http://localhost:8080
export OPENAI_API_KEY=sk-your-key-here
# LangChain picks up OPENAI_BASE_URL automatically — no code changes needed
```

## Tracing Integration

LangChain's LangSmith tracing and REVOC's X-Revoc-Trace-ID headers coexist:

```python
import os
os.environ["LANGCHAIN_TRACING_V2"] = "true"
os.environ["LANGCHAIN_API_KEY"] = "ls__your-key"

# Both LangSmith and REVOC traces are active simultaneously
# Find the REVOC trace ID in response headers: X-Revoc-Dashboard
```
