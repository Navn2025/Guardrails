from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.gaurdrails.input_gaurds import validate_input
from app.gaurdrails.outpiut_gaurds import validate_output
from app.gaurdrails.pii_detector import detect_and_redact_pii
from app.services.llm_service import get_llm_response

app = FastAPI(
    title="LLM Guardrails API",
    description="An API for validating LLM inputs and outputs",
    version="0.1.0",
)


class GuardrailRequest(BaseModel):
    text: str = Field(
        ...,
        description="The input text to validate.",
        min_length=1,
        max_length=10000,
    )
class LLMResponse(BaseModel):
    input: str = Field(
        ...,
        description="The input text sent to the LLM.",
    )
    response: str = Field(
        ...,
        description="The response from the LLM.",
    )
class LLMRequest(BaseModel):
    text: str = Field(
        ...,
        description="The input text to send to the LLM.",
        min_length=1,
        max_length=10000,
    )
    

class GuardrailResponse(BaseModel):
    allowed: bool = Field(
        ...,
        description="Whether the input is allowed.",
    )
    reason: str | None = Field(
        None,
        description="The reason for rejection, if applicable.",
    )
    risk_level: str = Field(
        ...,
        description="The risk level: low, medium, or high.",
    )
    rule_id: str | None = Field(
        None,
        description="The ID of the rule that triggered detection.",
    )
    category: str | None = Field(
        None,
        description="The category of the triggered rule.",
    )


@app.get("/")
async def read_root():
    return {"message": "LLM Guardrails API"}


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


@app.post(
    "/v1/guardrail/input",
    response_model=GuardrailResponse,
    summary="Validate user input against guardrail rules.",
)
async def validate_user_input(request: GuardrailRequest):
    result = validate_input(request.text)

    if not result.allowed:
        raise HTTPException(
            status_code=400,
            detail={
                "allowed": result.allowed,
                "reason": result.reason,
                "risk_level": result.risk_level,
                "rule_id": result.rule_id,
                "category": result.category,
            },
        )

    return GuardrailResponse(
        allowed=result.allowed,
        reason=result.reason,
        risk_level=result.risk_level,
        rule_id=result.rule_id,
        category=result.category,
    )

@app.post(
    "/v1/llm/response",
    response_model=LLMResponse,
    summary="Get LLM response for a given input.",
)
async def generate_llm_response(request: LLMRequest):
    """
    Get the response from the LLM for a given input.

    This endpoint validates the input against guardrail rules before sending it to the LLM.
    If the input is allowed, it returns the LLM's response. If not, it raises an HTTPException.
    """
    # Validate the input
    result = validate_input(request.text)

    if not result.allowed:
        raise HTTPException(
            status_code=400,
            detail={
                "allowed": result.allowed,
                "reason": result.reason,
                "risk_level": result.risk_level,
                "rule_id": result.rule_id,
                "category": result.category,
            },
        )
    redacted_text, pii_results = detect_and_redact_pii(request.text)
    # Get the LLM response
    try:
        llm_response = await get_llm_response(redacted_text)
    except Exception:
        raise HTTPException(status_code=502, detail="The model response is unavailable.") from None

    try:
        output_result = validate_output(llm_response)
    except TypeError:
        raise HTTPException(
            status_code=502,
            detail={"reason": "The model returned an invalid response type.", "reason_code": "invalid_output_type"},
        ) from None
    if not output_result.allowed:
        raise HTTPException(
            status_code=502,
            detail={
                "reason": output_result.reason,
                "reason_code": output_result.reason_code,
                "risk_level": output_result.risk_level,
                "rule_id": output_result.rule_id,
                "findings_count": output_result.findings_count,
                "detected_categories": output_result.detected_categories,
            },
        )

    return LLMResponse(
        input=redacted_text,
        response=output_result.safe_text,
    )


    
