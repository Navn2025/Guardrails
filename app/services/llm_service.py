
import asyncio
from functools import lru_cache

from dotenv import load_dotenv
from langchain_groq import ChatGroq



@lru_cache(maxsize=1)
def _get_model():
    # Initialize only for a real request, so imports/tests need no credentials.
    load_dotenv()
    return ChatGroq(model="openai/gpt-oss-120b")


async def get_llm_response(prompt: str) -> str:
    """
    Request raw model content. The API validates it before returning it.

    Args:
        prompt: The user's input prompt.

    Returns:
        The LLM's response as a string.
    """

    response = await _get_model().ainvoke(prompt)

    return response.content


if __name__ == "__main__":
    test_prompt = "Hello, how are you? my phone number is 123-456-7890 and my email is `user@example.com`"

    response = asyncio.run(
        get_llm_response(test_prompt)
    )

    from input_output_guardrails.app.gaurdrails.output_gaurds import validate_output

    result = validate_output(response)
    print(result.safe_text if result.allowed else "Output blocked.")
