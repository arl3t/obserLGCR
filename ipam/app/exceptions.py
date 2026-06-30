from fastapi import HTTPException, status


class IPAMError(Exception):
    def __init__(self, message: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


def raise_http_from_ipam(err: IPAMError) -> HTTPException:
    return HTTPException(status_code=err.status_code, detail=err.message)
