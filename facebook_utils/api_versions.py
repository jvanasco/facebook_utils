import datetime

# https://developers.facebook.com/docs/graph-api/changelog/versions
# Version:	Release Date, Expiration Date
_API_VERSIONS = {
    "8.0": ["Aug 4, 2020", None],
    "7.0": ["May 5, 2020", "Aug 4, 2022"],
    "6.0": ["Feb 3, 2020", "May 5, 2022"],
    "5.0": ["Oct 29, 2019", "Feb 3, 2022"],
    "4.0": ["Jul 29, 2019", "Nov 2, 2021"],
    "3.3": ["Apr 30, 2019", "Aug 3, 2021"],
    "3.2": ["Oct 23, 2018", "May 4, 2021"],
    "3.1": ["Jul 26, 2018", "Oct 27, 2020"],
    "3.0": ["May 1, 2018", "Jul 28, 2020"],
    "2.12": ["Jan 30, 2018", "May 5, 2020"],
    "2.11": ["Nov 7, 2017", "Jan 28, 2020"],
    "2.10": ["Jul 18, 2017", "Nov 7, 2019"],
    "2.9": ["Apr 18, 2017", "Jul 22, 2019"],
    "2.8": ["Oct 5, 2016", "Apr 18, 2019"],
    "2.7": ["Jul 13, 2016", "Oct 5, 2018"],
    "2.6": ["Apr 12, 2016", "Jul 13, 2018"],
    "2.5": ["Oct 7, 2015", "Apr 12, 2018"],
    "2.4": ["Jul 8, 2015", "Oct 9, 2017"],
    "2.3": ["Mar 25, 2015", "Jul 10, 2017"],
    "2.2": ["Oct 30, 2014", "Mar 27, 2017"],
    "2.1": ["Aug 7, 2014", "Oct 31, 2016"],
    "2.0": ["Apr 30, 2014", "Aug 8, 2016"],
    "1.0": ["Apr 21, 2010", "Apr 30, 2015"],
}
# >>> datetime.datetime.strptime("Apr 1, 2010", "%b %d, %Y")
_format = "%b %d, %Y"
API_VERSIONS = {}
for (_v, _ks) in _API_VERSIONS.items():
    API_VERSIONS[_v] = [
        datetime.datetime.strptime(_ks[0], _format),
        datetime.datetime.strptime(_ks[1], _format) if _ks[1] else None,
    ]
