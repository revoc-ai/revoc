"""
REVOC + LlamaIndex integration example — complete, runnable.

Before running:
    pip install llama-index llama-index-llms-openai llama-index-embeddings-openai
    docker run -d -p 8080:8080 -p 3000:3000 \
      -e OPENAI_API_KEY=$OPENAI_API_KEY \
      --name revoc ghcr.io/revoc-ai/revoc:beta
"""

import os
from llama_index.llms.openai import OpenAI
from llama_index.embeddings.openai import OpenAIEmbedding
from llama_index.core import Settings, VectorStoreIndex, Document

REVOC_BASE_URL = os.getenv("REVOC_BASE_URL", "http://localhost:8080")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "sk-mock")


def configure_revoc() -> None:
    """Point all LlamaIndex LLM and embedding calls at REVOC."""
    Settings.llm = OpenAI(
        model="gpt-4o-mini",
        api_base=REVOC_BASE_URL,
        api_key=OPENAI_API_KEY,
        temperature=0,
    )
    Settings.embed_model = OpenAIEmbedding(
        api_base=REVOC_BASE_URL,
        api_key=OPENAI_API_KEY,
    )


def demo_query_engine() -> None:
    """Build a VectorStoreIndex and query it — all LLM calls governed."""
    print("\n--- Query engine ---")
    documents = [
        Document(text="REVOC is a governance proxy that governs AI traffic in real time."),
        Document(text="REVOC detects PII, secrets, prompt injections, and SQL mutations."),
        Document(text="REVOC adds less than 10ms P95 overhead to LLM calls."),
    ]
    index = VectorStoreIndex.from_documents(documents)
    engine = index.as_query_engine(similarity_top_k=2)

    response = engine.query("What does REVOC detect?")
    print(f"Answer: {response}")


def demo_completion() -> None:
    """Direct LLM completion through REVOC."""
    print("\n--- Direct completion ---")
    llm = Settings.llm
    response = llm.complete("List three benefits of AI governance proxies.")
    print(f"Response: {response.text}")


def demo_secret_in_prompt_blocked() -> None:
    """Secret in prompt — REVOC blocks before LLM receives it."""
    print("\n--- Secret blocking (API key in prompt) ---")
    llm = Settings.llm
    try:
        llm.complete(
            "Use this key to call the API: sk-ant-api03-"
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        )
        print("Unexpected: not blocked")
    except Exception as e:
        print(f"Blocked as expected: {type(e).__name__}")


if __name__ == "__main__":
    print("REVOC + LlamaIndex Example")
    print(f"Proxy: {REVOC_BASE_URL}")
    print(f"Dashboard: http://localhost:3000")

    configure_revoc()
    demo_completion()
    demo_query_engine()
    demo_secret_in_prompt_blocked()

    print("\nDone. View traces at http://localhost:3000")
