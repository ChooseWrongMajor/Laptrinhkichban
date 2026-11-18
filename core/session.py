import boto3
from botocore.config import Config

# Retry chuẩn của AWS để tránh lỗi throttling khi quét nhiều tài nguyên
_BOTO_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})


class AwsSession:
    """Bọc boto3 Session: cache client theo (service, region) và lấy account ID."""

    def __init__(self, profile=None, region=None):
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self.default_region = self.session.region_name or "us-east-1"
        self._clients = {}
        self._account_id = None

    def client(self, service, region=None):
        region = region or self.default_region
        key = (service, region)
        if key not in self._clients:
            self._clients[key] = self.session.client(
                service, region_name=region, config=_BOTO_CONFIG
            )
        return self._clients[key]

    @property
    def account_id(self):
        if self._account_id is None:
            self._account_id = self.client("sts").get_caller_identity()["Account"]
        return self._account_id


def paginate(client, operation, result_key, **kwargs):
    """Duyệt hết các trang của một API list/describe và trả về từng phần tử."""
    if client.can_paginate(operation):
        for page in client.get_paginator(operation).paginate(**kwargs):
            yield from page.get(result_key, [])
    else:
        yield from getattr(client, operation)(**kwargs).get(result_key, [])


def chunks(items, size):
    """Chia danh sách thành các nhóm, dùng cho API giới hạn số phần tử mỗi lần gọi."""
    for i in range(0, len(items), size):
        yield items[i:i + size]
