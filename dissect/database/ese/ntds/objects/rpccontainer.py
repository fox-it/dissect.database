from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class RpcContainer(Top):
    """The default container for RPC endpoints.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-rpccontainer
    """

    __object_class__ = "rpcContainer"
