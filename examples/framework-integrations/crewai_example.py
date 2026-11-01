"""
REVOC + CrewAI integration example — complete, runnable.

Before running:
    pip install crewai langchain-openai
    docker run -d -p 8080:8080 -p 3000:3000 \
      -e OPENAI_API_KEY=$OPENAI_API_KEY \
      --name revoc ghcr.io/revoc-ai/revoc:beta
"""

import os
from crewai import Agent, Task, Crew, Process
from langchain_openai import ChatOpenAI

REVOC_BASE_URL = os.getenv("REVOC_BASE_URL", "http://localhost:8080")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "sk-mock")


def build_governed_llm() -> ChatOpenAI:
    """LangChain ChatOpenAI client routed through REVOC."""
    return ChatOpenAI(
        model="gpt-4o-mini",
        openai_api_base=REVOC_BASE_URL,
        openai_api_key=OPENAI_API_KEY,
        temperature=0,
    )


def demo_research_crew() -> None:
    """Two-agent crew: researcher + writer. Every LLM call governed by REVOC."""
    print("\n--- Research crew ---")
    llm = build_governed_llm()

    researcher = Agent(
        role="Research Analyst",
        goal="Research AI governance and summarize key points",
        backstory="Expert in AI safety with ten years of experience.",
        llm=llm,
        verbose=False,
        allow_delegation=False,
    )

    writer = Agent(
        role="Technical Writer",
        goal="Write clear, concise documentation",
        backstory="Skilled at turning research into accessible content.",
        llm=llm,
        verbose=False,
        allow_delegation=False,
    )

    research_task = Task(
        description="List three key risks of deploying AI agents without governance.",
        expected_output="Three bullet points, each one sentence.",
        agent=researcher,
    )

    writing_task = Task(
        description="Turn the research findings into a two-sentence executive summary.",
        expected_output="A two-sentence executive summary.",
        agent=writer,
        context=[research_task],
    )

    crew = Crew(
        agents=[researcher, writer],
        tasks=[research_task, writing_task],
        process=Process.sequential,
        verbose=False,
    )

    result = crew.kickoff()
    print(f"Crew output:\n{result}")


if __name__ == "__main__":
    print("REVOC + CrewAI Example")
    print(f"Proxy: {REVOC_BASE_URL}")
    print(f"Dashboard: http://localhost:3000")

    demo_research_crew()

    print("\nDone. View traces at http://localhost:3000")
