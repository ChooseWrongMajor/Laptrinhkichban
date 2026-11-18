def normalize_tags(tags):
    """
    Chuẩn hoá tag về dạng dict {key: value}.
    Mỗi service trả tag một kiểu khác nhau:
      EC2/ASG: [{"Key": .., "Value": ..}]
      ECS:     [{"key": .., "value": ..}]
      Lambda:  {"key": "value"}
    """
    if not tags:
        return {}
    if isinstance(tags, dict):
        return dict(tags)
    result = {}
    for tag in tags:
        key = tag.get("Key", tag.get("key"))
        value = tag.get("Value", tag.get("value", ""))
        if key is not None:
            result[key] = value
    return result


def parse_scope(expressions):
    """Chuyển danh sách 'Key=Value' từ CLI thành dict."""
    scope = {}
    for expr in expressions or []:
        if "=" not in expr:
            raise ValueError(f"Tag filter không hợp lệ: '{expr}', cần dạng Key=Value")
        key, value = expr.split("=", 1)
        scope[key] = value
    return scope


def in_scope(tags, scope):
    """Tài nguyên thuộc phạm vi nếu có đủ mọi tag trong scope (scope rỗng = mọi tài nguyên)."""
    if not scope:
        return True
    normalized = normalize_tags(tags)
    return all(normalized.get(k) == v for k, v in scope.items())
