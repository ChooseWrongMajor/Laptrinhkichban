from remediation.actions.base import planned, remediated


def require_iam_auth(url_config, ctx):
    """CIS 12.16 (tier A): chuyển Function URL sang AuthType=AWS_IAM."""
    name = url_config["FunctionName"]
    action = f"lambda.update_function_url_config({name}, AuthType=AWS_IAM)"
    rollback = (f"aws lambda update-function-url-config --region {ctx.region} "
                f"--function-name {name} --auth-type NONE")

    if ctx.dry_run:
        return planned(action, "Sẽ yêu cầu chữ ký SigV4 (IAM) cho mọi request tới Function URL; "
                               "client đang gọi không xác thực sẽ bị từ chối", rollback)

    ctx.client("lambda").update_function_url_config(FunctionName=name, AuthType="AWS_IAM")
    return remediated(action, "Function URL đã yêu cầu xác thực IAM", rollback)
