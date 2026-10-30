from input_output_guardrails.app.main import app
from pydantic import BaseModel,Field
from fastapi import HTTPException

from input_output_guardrails.app.gaurdrails.input_gaurds import validate_input, GuardrailResult

class GuardrailRequest(BaseModel):
    text: str = Field(..., description="The input text to validate.",min_length=1, max_length=10000)
class GuardrailResponse(BaseModel):
    allowed: bool = Field(..., description="Indicates whether the input is allowed or rejected.")
    reason: str | None = Field(None, description="The reason for rejection if the input is not allowed.")
    risk_level: str = Field(..., description="The risk level associated with the input (low, medium, high).")
    rule_id: str | None = Field(None, description="The ID of the rule that triggered the rejection, if applicable.")
    category: str | None = Field(None, description="The category of the rule that triggered the rejection, if applicable.")
@app.post("/v1/guardrail/input",
          response_model=GuardrailResponse,
          summary="Validate user input against guardrail rules.",
)
async def validate_user_input(request: GuardrailRequest):
    """
    Validate user input against guardrail rules.

    This endpoint analyzes the provided input text and returns a structured decision
    indicating whether the input is allowed or rejected based on predefined guardrail rules.
    """
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
