#!/usr/bin/env python3

"""
Event downloader from hub shares.

"""

import os
import re
import sys
import time
import gzip
import json
import argparse
import logging
import urllib.request
import urllib.error
from urllib.parse import urlparse, urlunparse, urljoin, parse_qs, urlencode, quote
from typing import Optional, Iterable, Tuple, Mapping, Union, List, Any

logger = logging.getLogger(__name__)

EventType = Mapping[str, Union[str, List[str]]]


def main(url, apikey, limit, debug, **params):
    """Script main function."""
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=log_level, format="%(asctime)s: %(message)s")

    url, headers, params, is_count_query = Preparation.prepare(url, apikey, params)

    if is_count_query:
        count = AsyncApi.count(url, headers, limit, params)
        _output(count=count)
    else:
        events = AsyncApi.poll(url, headers, limit, params)
        _output(events=events)
        print(params.get("token"), file=sys.stderr)


class Preparation:
    """Preparations before making the queries."""

    @classmethod
    def prepare(cls, url, apikey, params):
        url, apikey = cls._resolve_apikey(url, apikey)
        url = cls._sync_url_to_async_url(url)
        headers = cls._build_common_headers(apikey)
        params = cls._clean_and_encode_params(params)
        is_count_query = "/count" in url

        return url, headers, params, is_count_query

    @staticmethod
    def _resolve_apikey(url: str, apikey: Optional[str]) -> Tuple[str, str]:
        """Resolve apikey from url and/or parameter."""
        # Even though the async api doesn't support apikey query parameter,
        # for ease of use support providing it as query parameter in the url.
        # authorization is always done via Authorization header
        url, params = UrlManipulation.separate_query_params(url, ("apikey",))
        try:
            apikey = params["apikey"][0]
        except KeyError:
            pass

        if apikey is None:
            raise ValueError("apikey not defined")

        return url, apikey

    @staticmethod
    def _sync_url_to_async_url(url):
        """Convert sync share api url to corresponding async api url"""
        if "/async/" in url:
            return url

        o = urlparse(url)
        async_path = re.sub(r"^/shares(/v2)?", "/shares/v2/async", o.path)
        async_url = urlunparse(o._replace(path=async_path))
        logger.debug(f"{url} -> {async_url}")
        return async_url

    @staticmethod
    def _build_common_headers(apikey: str):
        """Build common headers for all the requests."""
        return {
            "Authorization": f"token {apikey}",
            "User-Agent": "sharing-api-fetcher",
            "Accept-Encoding": "gzip",
            "Accept": "application/json",
        }

    @staticmethod
    def _clean_and_encode_params(params: Mapping):
        """Clean and encode user provided params into query params."""
        # Keep only the parameters that were given a value
        params = {k: v for k, v in params.items() if v is not None}

        # All query parameters are later urlencoded - for projection, comma-separated
        # list is supported only on literal comma; convert comma-separated list
        # to a list of values which will be encoded to multiple query parameters
        try:
            params["projection"] = [x.strip() for x in params["projection"].split(",")]
        except KeyError:
            pass
        return params


class AsyncApi:
    """Sharing async api access functions."""

    @classmethod
    def poll(
        cls,
        url: str,
        headers: Mapping[str, str],
        limit: Optional[int],
        params: Mapping[str, Any],
    ) -> Iterable[EventType]:
        """Fetch events, handle retries.

        Load and generate all or up-to limit events from the api.

        The token (if any) for the following events is saved in params["token"].
        """
        # The sharing async api supports up-to 100k events per single request
        max_limit_per_query = 100_000
        n = 0
        while True:
            # Set limit for a single query
            if limit:
                params["limit"] = min(limit - n, max_limit_per_query)
            else:
                params["limit"] = max_limit_per_query

            try:
                events, next_token = cls._fetch(url, headers, params)
            except Retry as e:
                time.sleep(e.after)
            else:
                logger.debug(f"Loaded {len(events)} events")
                for event in events:
                    yield event

                n += len(events)
                params["token"] = next_token

                if n == limit or next_token is None:
                    # Requested number of events loaded or no more available
                    break

    @classmethod
    def count(
        cls,
        url: str,
        headers: Mapping[str, str],
        limit: Optional[int],
        params: Mapping[str, Any],
    ) -> int:
        """Get event count."""
        if limit:
            params["limit"] = limit

        while True:
            try:
                result, _ = cls._fetch(url, headers, params)
            except Retry as e:
                time.sleep(e.after)
            else:
                count = result["count"]
                logger.debug(f"Loaded count {count}")
                return count

    @classmethod
    def _fetch(
        cls, url: str, headers: Mapping[str, str], params: Mapping[str, Any]
    ) -> Tuple[List[EventType], Optional[str]]:
        """Fetch events / count from async api.

        Async API works in three phases:
        1) POST query to the API
        2) Poll query status
        3) Get query results
        """
        status_url = cls._post_query(url, headers, params)
        # Await a while before polling the results
        time.sleep(0.1)
        result_url = cls._poll_status(status_url, headers, params)
        data, headers = cls._get_results(result_url, headers, params)
        result = json.loads(data)
        return result, headers.get("x-next-token")

    @staticmethod
    def _post_query(url, headers, params):
        """Query phase 1/3: Post a query to the async api."""
        logger.debug(f"POST a query to {url}")
        # The query parameters applied for this request
        qp = (
            "start",
            "end",
            "filter",
            "projection",
            "sort",
            "reverse",
            "limit",
            "token",
        )
        code, resp_headers, data = http.request(url, headers, _pick(params, qp), "POST")
        if code == 503:
            raise Retry(resp_headers.get("Retry-After", 5))
        elif code != 202:
            raise QueryError(f"Unexpected status {code} for submit ({data})")
        else:
            return urljoin(url, resp_headers["Location"])

    @staticmethod
    def _poll_status(url, headers, params):
        """Query phase 2/3: Get result url from the async api."""
        logger.debug(f"GET status from {url}")
        qp = ()
        while True:
            code, resp_headers, data = http.request(url, headers, _pick(params, qp))
            if code == 302:  # results are ready
                break
            elif code == 202:  # results not ready yet
                time.sleep(int(resp_headers.get("Retry-After", 1)))
            elif code == 410:
                raise Retry("Results have been fetched by someone else")
            else:
                raise QueryError(f"Unexpected status {code} for status, {data}")

        return urljoin(url, resp_headers["Location"])

    @staticmethod
    def _get_results(url, headers, params):
        """Query phase 3/3: Get results."""
        logger.debug(f"GET results from {url}")
        qp = ()
        code, resp_headers, data = http.request(url, headers, _pick(params, qp))
        if code == 410:
            raise Retry("Results have been fetched already")
        elif code != 200:
            raise QueryError(f"Unexpected status {code} for results, {data}")

        return data, resp_headers


def _output(events: Optional[Iterable[EventType]] = None, count: Optional[int] = None):
    """Output events as json to stdout.

    json-encoding written manually here to avoid need to load all the events
    into memory at once.
    """
    if events is not None:
        print("[", end="")
        for i, event in enumerate(events):
            if i > 0:
                print(",", end="")
            print(f"{json.dumps(event)}", end="")
        print("]")
    else:
        print(f'{{"count": {count}}}')


def _pick(d, keys):
    """Pick only the defined keys from a dictionary."""
    return {k: v for k, v in d.items() if k in keys}


class QueryError(Exception):
    """API query error."""

    pass


class Retry(QueryError):
    """Query error which should be retried."""

    def __init__(self, *args, after=0, **kwargs):
        super().__init__(*args, **kwargs)
        self.after = after


class _Http:
    """HTTP access through urllib.

    The main purpose for the existence of this class is to wrap the urllib
    related code into a separate class.

    All the methods of this class should be accessed through http-variable.
    """

    def __init__(self):
        self._init_urllib()

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        """Handler to disable redirect on 302."""

        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            pass

    @classmethod
    def _init_urllib(cls):
        """Initialize urllib library."""
        # Disable automatic redirection
        handlers = (cls.NoRedirect(),)
        urllib.request.install_opener(urllib.request.build_opener(*handlers))

    @staticmethod
    def request(url, headers, params, method="GET"):
        """Construct and send a request."""
        url = UrlManipulation.replace_query_params(url, **params)
        logger.debug(f"request(): {method} {url}")
        req = urllib.request.Request(url, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                code = resp.code
                resp_headers = resp.info()
                data = resp.read()
        except urllib.error.HTTPError as e:
            code = e.code
            resp_headers = e.headers
            data = e.read()
        except urllib.error.URLError as e:
            raise QueryError(f"URLError: {e.reason}")

        if resp_headers.get("Content-Encoding", None) == "gzip":
            logger.debug("Decompress response")
            data = gzip.decompress(data)

        return code, resp_headers, data.decode()


http = _Http()


class UrlManipulation:
    """Methods for URL manipulation."""

    @staticmethod
    def add_query_params(
        url: str, **params: Mapping[str, Union[str, List[str]]]
    ) -> str:
        """Add query parameters to a url.
        >>> UrlManipulation.add_query_params("http://hub.example.com/index.html")
        'http://hub.example.com/index.html'
        >>> UrlManipulation.add_query_params("http://hub.example.com/index.html", foo="bar")
        'http://hub.example.com/index.html?foo=bar'
        >>> UrlManipulation.add_query_params("http://hub.example.com/index.html", foo="bar,baz")
        'http://hub.example.com/index.html?foo=bar%2Cbaz'
        >>> UrlManipulation.add_query_params("http://hub.example.com/index.html", foo=["bar","baz"])
        'http://hub.example.com/index.html?foo=bar&foo=baz'
        >>> UrlManipulation.add_query_params("http://hub.example.com/index.html", foo="bar", bar="baz")
        'http://hub.example.com/index.html?foo=bar&bar=baz'
        >>> UrlManipulation.add_query_params("http://hub.example.com/index.html?foo=bar", foo="baz")
        'http://hub.example.com/index.html?foo=bar&foo=baz'
        """
        o = urlparse(url)
        qp = parse_qs(o.query, keep_blank_values=True)

        for k, v in params.items():
            if isinstance(v, str):
                v = [v]
            try:
                qp[k].extend(v)
            except KeyError:
                qp[k] = v

        qs = urlencode(qp, doseq=True, quote_via=quote)
        return urlunparse(o._replace(query=qs))

    @staticmethod
    def separate_query_params(
        url: str, param_names: Optional[Iterable[str]] = None
    ) -> Tuple[str, Mapping[str, Iterable[str]]]:
        """Separate query parameters from url.

        If param_names is None, all query parameters are separated.
        Otherwise only the query parameters listed in param_names are separated.
        If parameter doesn't exist in query parameters, it is not added to the returned
        dict.

        >>> UrlManipulation.separate_query_params("http://hub.example.com")
        ('http://hub.example.com', {})
        >>> UrlManipulation.separate_query_params("http://hub.example.com?foo=bar&baz=qux")
        ('http://hub.example.com', {'foo': ['bar'], 'baz': ['qux']})
        >>> UrlManipulation.separate_query_params("http://hub.example.com?foo=bar&baz=qux", ("foo", "fuu"))
        ('http://hub.example.com?baz=qux', {'foo': ['bar']})
        >>> UrlManipulation.separate_query_params("http://hub.example.com?foo=bar&baz=qux", ())
        ('http://hub.example.com?foo=bar&baz=qux', {})
        >>> UrlManipulation.separate_query_params("http://hub.example.com?foo=bar&foo=baz")
        ('http://hub.example.com', {'foo': ['bar', 'baz']})
        >>> UrlManipulation.separate_query_params("http://hub.example.com?foo")
        ('http://hub.example.com', {'foo': ['']})
        >>> UrlManipulation.separate_query_params('http://hub.example.com?"foo%20bar"=baz')
        ('http://hub.example.com', {'"foo bar"': ['baz']})
        >>> UrlManipulation.separate_query_params('http://hub.example.com?"foo%20bar"=baz', ('"foo bar"',))
        ('http://hub.example.com', {'"foo bar"': ['baz']})
        """
        o = urlparse(url)
        qp = parse_qs(o.query, keep_blank_values=True)

        # Separate requested parameters from the query parameters
        params = {
            k: v for k, v in qp.items() if param_names is None or k in param_names
        }
        for p in params:
            qp.pop(p)

        # Rebuild url with the remaining query parameters
        qs = urlencode(qp, doseq=True, quote_via=quote)
        url = urlunparse(o._replace(query=qs))

        return url, params

    @classmethod
    def replace_query_params(cls, url: str, **params: Mapping[str, str]) -> str:
        """Replace query parameters from url."""
        url, _ = cls.separate_query_params(url, params.keys())
        return cls.add_query_params(url, **params)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--apikey", "-k", default=os.environ.get("APIKEY"))
    parser.add_argument("--limit", "-n", type=int, help="Max events to fetch")
    parser.add_argument("--token", "-t", help="Query token")
    parser.add_argument("--start", "-s", help="Query start time (only API query)")
    parser.add_argument("--end", "-e", help="Query end time (only API query)")
    parser.add_argument("--filter", "-q", help="Query filter (only API query)")
    parser.add_argument("--projection", "-p", help="Query projection (only API query)")
    parser.add_argument("--sort", help="Query sort key (only API query)")
    parser.add_argument(
        "--reverse", action="store_true", help="Sort in reverse? (only API query)"
    )
    parser.add_argument(
        "--debug", action="store_true", help="Print debug info to stderr"
    )
    parser.add_argument("url", help="API url")
    sys.exit(main(**vars(parser.parse_args())))
