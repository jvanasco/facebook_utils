# stdlib
import datetime
from typing import Dict
from typing import Optional
from typing import Tuple


# ==============================================================================

TYPE_API_VERSION_INFO = Tuple[datetime.date, Optional[datetime.date]]
TYPE_API_VERSIONS = Dict[str, TYPE_API_VERSION_INFO]

# last checked 2025/08/12
# https://developers.facebook.com/docs/graph-api/changelog/versions
# Version:	Release Date, Expiration Date
_TYPE_API_RAW_INFO = Tuple[str, Optional[str]]
_TYPE_API_VERSIONS_RAW = Dict[str, _TYPE_API_RAW_INFO]
_API_VERSIONS: _TYPE_API_VERSIONS_RAW = {
    "23.0": ("May 29, 2025", None),
    "22.0": ("Jan 21, 2025", None),
    "21.0": ("Oct 2, 2024", None),
    "20.0": ("May 21, 2024", "Sep 24, 2026"),
    "19.0": ("Jan 23, 2024", "May 21, 2036"),
    "18.0": ("Sep 12, 2023", "Jan 26, 2026"),
    "17.0": ("May 23, 2023", "Sep 12, 2025"),
    "16.0": ("Feb 2, 2023", "May 14, 2025"),
    "15.0": ("Sep 15, 2022", "Nov 20, 2024"),
    "14.0": ("May 25, 2022", "Sep 17, 2024"),
    "13.0": ("Feb 8, 2022", "May 28, 2024"),
    "12.0": ("Sep 14, 2021", "Feb 8, 2024"),
    "11.0": ("Jun 8, 2021", "Sep 14, 2023"),
    "10.0": ("Feb 23, 2021", "Jun 8, 2023"),
    "9.0": ("Nov 10, 2020", "Feb 23, 2023"),
    "8.0": ("Aug 4, 2020", "Nov 1, 2022"),
    "7.0": ("May 5, 2020", "Aug 4, 2022"),
    "6.0": ("Feb 3, 2020", "May 5, 2022"),
    "5.0": ("Oct 29, 2019", "Feb 3, 2022"),
    "4.0": ("Jul 29, 2019", "Nov 2, 2021"),
    "3.3": ("Apr 30, 2019", "Aug 3, 2021"),
    "3.2": ("Oct 23, 2018", "May 4, 2021"),
    "3.1": ("Jul 26, 2018", "Oct 27, 2020"),
    "3.0": ("May 1, 2018", "Jul 28, 2020"),
    "2.12": ("Jan 30, 2018", "May 5, 2020"),
    "2.11": ("Nov 7, 2017", "Jan 28, 2020"),
    "2.10": ("Jul 18, 2017", "Nov 7, 2019"),
    "2.9": ("Apr 18, 2017", "Jul 22, 2019"),
    "2.8": ("Oct 5, 2016", "Apr 18, 2019"),
    "2.7": ("Jul 13, 2016", "Oct 5, 2018"),
    "2.6": ("Apr 12, 2016", "Jul 13, 2018"),
    "2.5": ("Oct 7, 2015", "Apr 12, 2018"),
    "2.4": ("Jul 8, 2015", "Oct 9, 2017"),
    "2.3": ("Mar 25, 2015", "Jul 10, 2017"),
    "2.2": ("Oct 30, 2014", "Mar 27, 2017"),
    "2.1": ("Aug 7, 2014", "Oct 31, 2016"),
    "2.0": ("Apr 30, 2014", "Aug 8, 2016"),
    "1.0": ("Apr 21, 2010", "Apr 30, 2015"),
}

# >>> datetime.datetime.strptime("Apr 1, 2010", "%b %d, %Y")
_format = "%b %d, %Y"
API_VERSIONS: TYPE_API_VERSIONS = {}
for _v, _ks in _API_VERSIONS.items():
    API_VERSIONS[_v] = (
        datetime.datetime.strptime(_ks[0], _format).date(),
        datetime.datetime.strptime(_ks[1], _format).date() if _ks[1] else None,
    )
