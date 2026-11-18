from functools import wraps

from core.models import ERROR, Finding


def evaluator(cis_id, id_of, name_of=lambda r: ""):
    """
    Decorator cho hàm đánh giá một tài nguyên.

    Hàm được bọc nhận (resource, ctx) và trả về (status, message, evidence).
    Decorator lo phần lặp lại:
      - tạo Finding với resource_id / resource_name / region
      - tài nguyên có "_error" (lỗi khi thu thập) -> ERROR
      - hàm đánh giá ném exception (thiếu field...) -> ERROR
    """
    def decorate(func):
        @wraps(func)
        def wrapper(resource, ctx):
            base = {
                "cis_id": cis_id,
                "resource_id": id_of(resource),
                "resource_name": name_of(resource),
                "region": ctx.region,
            }
            if "_error" in resource:
                return Finding(**base, status=ERROR, message=resource["_error"])
            try:
                status, message, evidence = func(resource, ctx)
            except Exception as exc:  # noqa: BLE001 - mọi lỗi đánh giá đều ghi nhận là ERROR
                return Finding(**base, status=ERROR,
                               message=f"Lỗi khi đánh giá: {type(exc).__name__}: {exc}")
            return Finding(**base, status=status, message=message, evidence=evidence)
        return wrapper
    return decorate
