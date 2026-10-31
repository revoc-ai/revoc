# CrewAI Integration

REVOC governs CrewAI agent crews by intercepting all LLM calls. Every agent in the crew
is governed independently, and tool calls are inspected before execution.

## Prerequisites

```bash
pip install crewai crewai-tools openai
docker run -d -p 8080:8080 -p 3000:3000 \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  --name revoc ghcr.io/revoc-ai/revoc:latest
```

## Basic Crew

```python
import os
from crewai import Agent, Task, Crew, Process
from langchain_openai import ChatOpenAI

# All crew LLM calls go through REVOC
os.environ["OPENAI_API_BASE"] = "http://localhost:8080"
os.environ["OPENAI_API_KEY"] = "sk-your-key-here"

llm = ChatOpenAI(
    model="gpt-4o-mini",
    openai_api_base="http://localhost:8080",
    openai_api_key="sk-your-key-here",
)

researcher = Agent(
    role="Senior Research Analyst",
    goal="Research AI governance trends and best practices",
    backstory="You are an expert in AI safety and governance.",
    llm=llm,
    verbose=True,
)

writer = Agent(
    role="Content Strategist",
    goal="Write compelling content about AI governance",
    backstory="You craft clear technical documentation.",
    llm=llm,
    verbose=True,
)

research_task = Task(
    description="Research the top 3 risks in uncontrolled AI agent deployments.",
    expected_output="A bullet-point list of 3 risks with brief descriptions.",
    agent=researcher,
)

writing_task = Task(
    description="Write a 200-word executive summary of the research findings.",
    expected_output="A 200-word executive summary suitable for a board presentation.",
    agent=writer,
    context=[research_task],
)

crew = Crew(
    agents=[researcher, writer],
    tasks=[research_task, writing_task],
    process=Process.sequential,
    verbose=True,
)

# Every LLM call in every agent turn passes through REVOC
result = crew.kickoff()
print(result)
```

## Crew with Database Tool Governance

```python
import os
from crewai import Agent, Task, Crew, Tool
from langchain_openai import ChatOpenAI

os.environ["OPENAI_API_BASE"] = "http://localhost:8080"
os.environ["OPENAI_API_KEY"] = "sk-your-key-here"

llm = ChatOpenAI(
    model="gpt-4o-mini",
    openai_api_base="http://localhost:8080",
    openai_api_key="sk-your-key-here",
)

def run_analytics_query(query: str) -> str:
    """Run a read-only analytics query. Only SELECT statements are permitted."""
    # REVOC inspects the query argument via MCP tool governance
    # DROP, TRUNCATE, DELETE without WHERE are blocked before this function runs
    if not query.strip().upper().startswith("SELECT"):
        return "Error: only SELECT queries are permitted"
    return f"Query executed successfully. Result: 142 rows returned."

analytics_tool = Tool(
    name="run_analytics_query",
    description="Execute a read-only SQL SELECT query against the analytics database.",
    func=run_analytics_query,
)

data_analyst = Agent(
    role="Data Analyst",
    goal="Analyze customer data and produce insights",
    backstory="You are a senior data analyst with SQL expertise.",
    tools=[analytics_tool],
    llm=llm,
    verbose=True,
)

analysis_task = Task(
    description="Find the top 5 customers by revenue in the last 30 days.",
    expected_output="A ranked list of 5 customers with their revenue figures.",
    agent=data_analyst,
)

crew = Crew(agents=[data_analyst], tasks=[analysis_task], verbose=True)

# If the agent generates a dangerous SQL query, REVOC blocks it
# before the run_analytics_query function receives the call
result = crew.kickoff()
print(result)
```

## Environment Variable Configuration

CrewAI uses LangChain under the hood and respects the `OPENAI_API_BASE` environment variable:

```bash
# Zero-code-change governance for any CrewAI application
export OPENAI_API_BASE=http://localhost:8080
export OPENAI_API_KEY=sk-your-key-here
python your_crew_script.py
```

## Viewing Crew Governance in the Dashboard

Each agent turn appears as a separate trace in the REVOC dashboard at `:3000`.
The `caller_id` is set from the API key used, and you can filter by:

- Agent name (set via `X-Revoc-Caller-ID` header if using the SDK)
- Decision (allow/redact/block)
- Rule violations
- Time range matching your crew execution window
