from audit.checks.base import evaluator
from core.models import FAIL, PASS


@evaluator("12.16", lambda u: u["FunctionArn"], lambda u: u["FunctionName"])
def function_url_iam_auth(url_config, ctx):
    """CIS 12.16: Function URL phải dùng AuthType = AWS_IAM."""
    auth_type = url_config["AuthType"]
    evidence = {"auth_type": auth_type, "function_url": url_config.get("FunctionUrl", "")}
    if auth_type == "AWS_IAM":
        return PASS, "Function URL yêu cầu xác thực IAM", evidence
    return FAIL, f"Function URL dùng AuthType = {auth_type}, không cần xác thực", evidence
