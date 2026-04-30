from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSImagingPSPs(Top):
    """Container for all Enterprise Scan Post Scan Process objects.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msimaging-psps
    """

    __object_class__ = "msImaging-PSPs"
