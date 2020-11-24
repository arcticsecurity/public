> This document is classified by the Traffic Light Protocol (TLP) as **TLP:WHITE**.

# Arctic Hub: Sharing Asynchronous API Downloader

This `README.md` describes the script `async.py`, which is an example on how to use the Arctic Hub async share API.

# Script `async.py`

Script `async.py` demonstrates

- async api usage
- common error handling
- paging

## Usage

The basic usage is

`> ./async.py <url> --apikey <key>`

which downloads the events from the provided url. Query parameters can be given with command line arguments.

The downloaded events (or event count) will be written as json to `stdout`. When downloading events and there are more events available, the final `X-Next-Token` value is written to `stderr`.

See `./async.py --help` or `python3 async.py --help` for more details.

All command line arguments are urlencoded into http query parameters automatically.

Script usage examples are listed below. The examples assume the `apikey` is defined in environment variable `APIKEY`.

- `./async.py https://hub.example.com/shares/v2/async/:id`
  - Download all events from api share `:id`.
- `./async.py https://hub.example.com/shares/v2/async/:id/:index`
  - Download all events from notification share `:id` index `:index`.
- `./async.py https://hub.example.com/shares/v2/async/:id/count`
  - Get event count from api share `:id`.
- `./async.py https://hub.example.com/shares/v2/async/:id --start=2020-10-01 --end=2020-10-07`
  - Download events from api share `:id` from the specified time range. It should be noted that the time range may also be limited by the share configuration.
- `./async.py https://hub.example.com/shares/v2/async/:id --limit=100 --reverse`
  - Download up to 100 newest events from api share `:id`.
- `./async.py https://hub.example.com/shares/v2/async/:id --limit=10000 --token=<token> --projection="feed,observation time"`
  - Download up to 10000 events, continue from `<token>` which is typically obtained from a previous call to the api, project keys `feed` and `observation time`.

## Requirements

The script works with python 3.6 and newer. There are no other external dependencies. The http request handling in python is typically implemented with [requests](https://requests.readthedocs.io/) package. However, to make the script standalone everything is implemented with python standard library only.

## Structure

The script contains the following classes:

- `Preparation`
- `AsyncApi`
- `_Http`
- `UrlManipulation`

`Preparation` is used to convert the script input to async api input. `_Http` and `UrlManipulation` are helper classes to make `urllib` usage more straightforward.

The actual sharing API usage is implemented in `AsyncApi`. The class has two public member functions; `AsyncApi.poll()` implements downloading events from the API, and `AsyncApi.count()` implements getting an event count from the API. Both functions use `AsyncApi._fetch()` to communicate with the sharing async api.

The functionality implemented by `AsyncApi._fetch()` is described [below](#one-query).

## API Key

All async api requests require an apikey in an `Authorization`-header. The key can be given with command line argument `--apikey` or defined in an environment variable `APIKEY`.

The script also supports urls in which `apikey` is configured as a query parameter. The `apikey` is separated from the url automatically and placed in the `Authorization`-header. This is supported to make it easier to copy & paste urls.

## Sync URL Support

The script can automatically convert sync api urls to corresponding async api url. This is supported to make it easy to use urls copied from the hub UI.

# Sharing Async API

## One Query

One query to the async api consists of three phases:

1. Post the query
2. Poll query job status
3. Download query results

These phases are the same for both API shares and notification shares, but the notification shares support fewer query parameters.

### Posting the Query

The query is `POST`ed to one of the following urls

- `/shares/v2/async/:id`
- `/shares/v2/async/:id/:index`
- `/shares/v2/async/:id/count`
- `/shares/v2/async/:id/:index/count`

The urls with `:index` refer to notification shares and the ones without to api shares. The urls with `/count` return the event count, and the ones without the events itself.

The query parameters are passed to this url. When polling the query job status or downloading the job results the query parameters are not accepted.

If the query was accepted, the API returns status `202` and an url where to poll the job status in the `Location` header. The url is relative [1, 2].

### Polling the Status

The status url obtained from phase 1 of the query can be used to get the query job status.

- `/shares/v2/async/:id/jobs/:jid`

A successful `GET` request on that url returns one of the following

- `302` if job finished, url to fetch results provided in `Location`-header.
- `202` if job found but not finished yet, status url provided in `Location`-header.

### Downloading the Query Results

Once the query job is finished, the query results may be downloaded from the url obtained from phase 2 of the query.

- `/shares/v2/async/:id/results/:jid`

A `GET` request on that url may return one of the following

- `200` events or event count
- `410` if job found, finished, but results already fetched
- `404` if share not found or job not found or job already removed

## Pagination

The maximum number of events that can be downloaded with one query is limited. If there are more events available than can be provided in the query, `X-Next-Token` header is included when downloading the results. More events can then be downloaded with a new query by passing the token value in query parameter `token`.


# References

- [1] https://tools.ietf.org/html/rfc7231#section-7.1.2
- [2] https://tools.ietf.org/html/rfc3986#section-4.2
