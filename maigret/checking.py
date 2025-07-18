# Standard library imports
import asyncio
import logging
import random
import re
import ssl
import sys
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote


# Third party imports
import aiodns
from aiohttp import ClientSession, TCPConnector, http_exceptions
from aiohttp.client_exceptions import ClientConnectorError, ServerDisconnectedError
from alive_progress import alive_bar
from python_socks import _errors as proxy_errors

try:
    from mock import Mock
except ImportError:
    from unittest.mock import Mock

# Local imports
from . import errors
from .activation import ParsingActivator, import_aiohttp_cookies
from .errors import CheckError
from .executors import AsyncioQueueGeneratorExecutor
from .result import MaigretCheckResult, MaigretCheckStatus, MaigretResults
from .sites import MaigretSite
from .types import QueryOptions, QueryResultWrapper
from .utils import (
    extract_ids_data,
    get_random_user_agent,
    parse_usernames,
    update_results_info,
)


SUPPORTED_IDS = (
    "username",
    "yandex_public_id",
    "gaia_id",
    "vk_id",
    "ok_id",
    "wikimapia_uid",
    "steam_id",
    "uidme_uguid",
    "yelp_userid",
)

BAD_CHARS = "#"


class CheckerBase:
    pass


class SimpleAiohttpChecker(CheckerBase):
    def __init__(self, *args, **kwargs):
        self.proxy = kwargs.get('proxy')
        self.cookie_jar = kwargs.get('cookie_jar')
        self.logger = kwargs.get('logger', Mock())
        self.url = None
        self.headers = None
        self.allow_redirects = True
        self.timeout = 0
        self.method = 'get'
        self.activator = None

    def prepare(self, url, headers=None, allow_redirects=True, timeout=0, method='get'):
        self.url = url
        self.headers = headers
        self.allow_redirects = allow_redirects
        self.timeout = timeout
        self.method = method
        return None

    async def close(self):
        pass

    async def _make_request(
        self, session, url, headers, allow_redirects, timeout, method, logger
    ) -> Tuple[str, int, Optional[CheckError]]:
        try:
            request_method = session.get if method == 'get' else session.head
            async with request_method(
                url=url,
                headers=headers,
                allow_redirects=allow_redirects,
                timeout=timeout,
            ) as response:
                status_code = response.status
                response_content = await response.content.read()
                charset = response.charset or "utf-8"
                decoded_content = response_content.decode(charset, "ignore")

                error = CheckError("Connection lost") if status_code == 0 else None
                logger.debug(decoded_content)

                return decoded_content, status_code, error

        except asyncio.TimeoutError as e:
            return None, 0, CheckError("Request timeout", str(e))
        except ClientConnectorError as e:
            return None, 0, CheckError("Connecting failure", str(e))
        except ServerDisconnectedError as e:
            return None, 0, CheckError("Server disconnected", str(e))
        except http_exceptions.BadHttpMessage as e:
            return None, 0, CheckError("HTTP", str(e))
        except proxy_errors.ProxyError as e:
            return None, 0, CheckError("Proxy", str(e))
        except KeyboardInterrupt:
            return None, 0, CheckError("Interrupted")
        except Exception as e:
            if sys.version_info.minor > 6 and (
                isinstance(e, ssl.SSLCertVerificationError)
                or isinstance(e, ssl.SSLError)
            ):
                return None, 0, CheckError("SSL", str(e))
            else:
                logger.debug(e, exc_info=True)
                return None, 0, CheckError("Unexpected", str(e))

    async def check(self) -> Tuple[str, int, Optional[CheckError]]:
        from aiohttp_socks import ProxyConnector

        connector = (
            ProxyConnector.from_url(self.proxy)
            if self.proxy
            else TCPConnector(ssl=False)
        )
        connector.verify_ssl = False

        async with ClientSession(
            connector=connector,
            trust_env=True,
            # TODO: tests
            cookie_jar=self.cookie_jar if self.cookie_jar else None,
        ) as session:
            self.activator = ParsingActivator(session)
            html_text, status_code, error = await self._make_request(
                session,
                self.url,
                self.headers,
                self.allow_redirects,
                self.timeout,
                self.method,
                self.logger,
            )

            if error and str(error) == "Invalid proxy response":
                self.logger.debug(error, exc_info=True)

            return str(html_text) if html_text else '', status_code, error


class ProxiedAiohttpChecker(SimpleAiohttpChecker):
    def __init__(self, *args, **kwargs):
        self.proxy = kwargs.get('proxy')
        self.cookie_jar = kwargs.get('cookie_jar')
        self.logger = kwargs.get('logger', Mock())


class AiodnsDomainResolver(CheckerBase):
    if sys.platform == 'win32':  # Temporary workaround for Windows
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    def __init__(self, *args, **kwargs):
        loop = asyncio.get_event_loop()
        self.logger = kwargs.get('logger', Mock())
        self.resolver = aiodns.DNSResolver(loop=loop)

    def prepare(self, url, headers=None, allow_redirects=True, timeout=0, method='get'):
        self.url = url
        return None

    async def check(self) -> Tuple[str, int, Optional[CheckError]]:
        status = 404
        error = None
        text = ''

        try:
            res = await self.resolver.query(self.url, 'A')
            text = str(res[0].host)
            status = 200
        except aiodns.error.DNSError:
            pass
        except Exception as e:
            self.logger.error(e, exc_info=True)
            error = CheckError('DNS resolve error', str(e))

        return text, status, error


class CheckerMock:
    def __init__(self, *args, **kwargs):
        pass

    def prepare(self, url, headers=None, allow_redirects=True, timeout=0, method='get'):
        return None

    async def check(self) -> Tuple[str, int, Optional[CheckError]]:
        await asyncio.sleep(0)
        return '', 0, None

    async def close(self):
        return


# TODO: move to separate class
def detect_error_page(
    html_text, status_code, fail_flags, ignore_403
) -> Optional[CheckError]:
    # Detect service restrictions such as a country restriction
    for flag, msg in fail_flags.items():
        if flag in html_text:
            return CheckError("Site-specific", msg)

    # Detect common restrictions such as provider censorship and bot protection
    err = errors.detect(html_text)
    if err:
        return err

    # Detect common site errors
    if status_code == 403 and not ignore_403:
        return CheckError("Access denied", "403 status code, use proxy/vpn")

    elif status_code >= 500:
        return CheckError("Server", f"{status_code} status code")

    return None


def debug_response_logging(url, html_text, status_code, check_error):
    with open("debug.log", "a") as f:
        status = status_code or "No response"
        f.write(f"url: {url}\nerror: {check_error}\nr: {status}\n")
        if html_text:
            f.write(f"code: {status}\nresponse: {str(html_text)}\n")


async def process_site_result(
    response, query_notify, logger, results_info: QueryResultWrapper, site: MaigretSite, checker: CheckerBase
):
    if not response:
        return results_info

    fulltags = site.tags

    # Retrieve other site information again
    username = results_info["username"]
    is_parsing_enabled = results_info["parsing_enabled"]
    url = results_info.get("url_user")
    logger.info(url)

    status = results_info.get("status")
    if status is not None:
        # We have already determined the user doesn't exist here
        return results_info

    # Get the expected check type
    check_type = site.check_type

    # TODO: refactor
    if not response:
        logger.error(f"No response for {site.name}")
        return results_info

    html_text, status_code, check_error = response

    # TODO: add elapsed request time counting
    response_time = None

    if logger.level == logging.DEBUG:
        debug_response_logging(url, html_text, status_code, check_error)

    # additional check for errors
    if status_code and not check_error:
        check_error = detect_error_page(
            html_text, status_code, site.errors_dict, site.ignore403
        )

    # parsing activation
    is_need_activation = any(
        [s for s in site.activation.get("marks", []) if s in html_text]
    )

    if site.activation and html_text and is_need_activation:
        logger.debug(f"Activation for {site.name}")
        method = site.activation["method"]
        try:
            activator = checker.activator
            activate_fun = getattr(activator, method)
            await activate_fun(site, logger)
        except AttributeError:
            logger.warning(
                f"Activation method {method} for site {site.name} not found!",
                exc_info=True,
            )
        except Exception as e:
            logger.warning(
                f"Failed activation {method} for site {site.name}: {str(e)}",
                exc_info=True,
            )
        # TODO: temporary check error

    site_name = site.pretty_name
    # presense flags
    # True by default
    presense_flags = site.presense_strs
    is_presense_detected = False

    if html_text:
        if not presense_flags:
            is_presense_detected = True
            site.stats["presense_flag"] = None
        else:
            for presense_flag in presense_flags:
                if presense_flag in html_text:
                    is_presense_detected = True
                    site.stats["presense_flag"] = presense_flag
                    logger.debug(presense_flag)
                    break

    def build_result(status, **kwargs):
        return MaigretCheckResult(
            username,
            site_name,
            url,
            status,
            query_time=response_time,
            tags=fulltags,
            **kwargs,
        )

    if check_error:
        logger.warning(check_error)
        result = MaigretCheckResult(
            username,
            site_name,
            url,
            MaigretCheckStatus.UNKNOWN,
            query_time=response_time,
            error=check_error,
            context=str(CheckError),
            tags=fulltags,
        )
    elif check_type == "message":
        # Checks if the error message is in the HTML
        is_absence_detected = any(
            [(absence_flag in html_text) for absence_flag in site.absence_strs]
        )
        if not is_absence_detected and is_presense_detected:
            result = build_result(MaigretCheckStatus.CLAIMED)
        else:
            result = build_result(MaigretCheckStatus.AVAILABLE)
    elif check_type in "status_code":
        # Checks if the status code of the response is 2XX
        if 200 <= status_code < 300:
            result = build_result(MaigretCheckStatus.CLAIMED)
        else:
            result = build_result(MaigretCheckStatus.AVAILABLE)
    elif check_type == "response_url":
        # For this detection method, we have turned off the redirect.
        # So, there is no need to check the response URL: it will always
        # match the request.  Instead, we will ensure that the response
        # code indicates that the request was successful (i.e. no 404, or
        # forward to some odd redirect).
        if 200 <= status_code < 300 and is_presense_detected:
            result = build_result(MaigretCheckStatus.CLAIMED)
        else:
            result = build_result(MaigretCheckStatus.AVAILABLE)
    else:
        # It should be impossible to ever get here...
        raise ValueError(
            f"Unknown check type '{check_type}' for " f"site '{site.name}'"
        )

    extracted_ids_data = {}

    if is_parsing_enabled and result.status == MaigretCheckStatus.CLAIMED:
        extracted_ids_data = extract_ids_data(html_text, logger, site)
        if extracted_ids_data:
            new_usernames = parse_usernames(extracted_ids_data, logger)
            results_info = update_results_info(
                results_info, extracted_ids_data, new_usernames
            )
            result.ids_data = extracted_ids_data

    # Save status of request
    results_info["status"] = result

    # Save results from request
    results_info["http_status"] = status_code
    results_info["is_similar"] = site.similar_search
    # results_site['response_text'] = html_text
    results_info["rank"] = site.alexa_rank
    return results_info


def make_site_result(
    site: MaigretSite, username: str, options: QueryOptions, logger, *args, **kwargs
) -> QueryResultWrapper:
    results_site: QueryResultWrapper = {}

    # Record URL of main site and username
    results_site["site"] = site
    results_site["username"] = username
    results_site["parsing_enabled"] = options["parsing"]
    results_site["url_main"] = site.url_main
    results_site["cookies"] = (
        options.get("cookie_jar")
        and options["cookie_jar"].filter_cookies(site.url_main)
        or None
    )

    headers = {
        "User-Agent": get_random_user_agent(),
        # tell server that we want to close connection after request
        "Connection": "close",
    }

    headers.update(site.headers)

    if "url" not in site.__dict__:
        logger.error("No URL for site %s", site.name)

    if kwargs.get('retry') and hasattr(site, "mirrors"):
        site.url_main = random.choice(site.mirrors)
        logger.info(f"Use {site.url_main} as a main url of site {site}")

    # URL of user on site (if it exists)
    url = site.url.format(
        urlMain=site.url_main, urlSubpath=site.url_subpath, username=quote(username)
    )

    # workaround to prevent slash errors
    url = re.sub("(?<!:)/+", "/", url)

    # always clearweb_checker for now
    checker = options["checkers"][site.protocol]

    # site check is disabled
    if site.disabled and not options['forced']:
        logger.debug(f"Site {site.name} is disabled, skipping...")
        results_site["status"] = MaigretCheckResult(
            username,
            site.name,
            url,
            MaigretCheckStatus.ILLEGAL,
            error=CheckError("Check is disabled"),
        )
    # current username type could not be applied
    elif site.type != options["id_type"]:
        results_site["status"] = MaigretCheckResult(
            username,
            site.name,
            url,
            MaigretCheckStatus.ILLEGAL,
            error=CheckError('Unsupported identifier type', f'Want "{site.type}"'),
        )
    # username is not allowed.
    elif site.regex_check and re.search(site.regex_check, username) is None:
        results_site["status"] = MaigretCheckResult(
            username,
            site.name,
            url,
            MaigretCheckStatus.ILLEGAL,
            error=CheckError(
                'Unsupported username format', f'Want "{site.regex_check}"'
            ),
        )
        results_site["url_user"] = ""
        results_site["http_status"] = ""
        results_site["response_text"] = ""
        # query_notify.update(results_site["status"])
    else:
        # URL of user on site (if it exists)
        results_site["url_user"] = url
        url_probe = site.url_probe
        if url_probe is None:
            # Probe URL is normal one seen by people out on the web.
            url_probe = url
        else:
            # There is a special URL for probing existence separate
            # from where the user profile normally can be found.
            url_probe = url_probe.format(
                urlMain=site.url_main,
                urlSubpath=site.url_subpath,
                username=username,
            )

        for k, v in site.get_params.items():
            url_probe += f"&{k}={v}"

        if site.check_type == "status_code" and site.request_head_only:
            # In most cases when we are detecting by status code,
            # it is not necessary to get the entire body:  we can
            # detect fine with just the HEAD response.
            request_method = 'head'
        else:
            # Either this detect method needs the content associated
            # with the GET response, or this specific website will
            # not respond properly unless we request the whole page.
            request_method = 'get'

        if site.check_type == "response_url":
            # Site forwards request to a different URL if username not
            # found.  Disallow the redirect so we can capture the
            # http status from the original URL request.
            allow_redirects = False
        else:
            # Allow whatever redirect that the site wants to do.
            # The final result of the request will be what is available.
            allow_redirects = True

        future = checker.prepare(
            method=request_method,
            url=url_probe,
            headers=headers,
            allow_redirects=allow_redirects,
            timeout=options['timeout'],
        )

        # Store future request object in the results object
        results_site["future"] = future

    results_site["checker"] = checker

    return results_site


async def check_site_for_username(
    site, username, options: QueryOptions, logger, query_notify, *args, **kwargs
) -> Tuple[str, QueryResultWrapper]:
    default_result = make_site_result(
        site, username, options, logger, retry=kwargs.get('retry')
    )

    checker = default_result.get("checker")
    if not checker:
        print(f"error, no checker for {site.name}")
        return site.name, default_result

    response = await checker.check()

    response_result = await process_site_result(
        response, query_notify, logger, default_result, site, checker
    )

    query_notify.update(response_result['status'], site.similar_search)

    return site.name, response_result

def get_failed_sites(results: Dict[str, QueryResultWrapper]) -> List[str]:
    sites = []
    for sitename, r in results.items():
        status = r.get('status', {})
        if status and status.error:
            if errors.is_permanent(status.error.type):
                continue
            sites.append(sitename)
    return sites


async def maigret(
    username: str,
    site_dict: Dict[str, MaigretSite],
    logger,
    query_notify=None,
    **kwargs
) -> Dict[str, QueryResultWrapper]:

    # TODO: add other options
    options = QueryOptions(
        username=username,
        site_dict=site_dict,
        **kwargs
    )

    if not query_notify:
        query_notify = MaigretResults(
            username=username,
            known_accounts=[],
            skipped_sites=[],
        )

    # if options['no_recursion']:
    #     options['parsing'] = False

    # if options['proxy'] and options['proxy'].startswith('tor'):
    #     logger.info('Using Tor proxy')
    #     options['tor_proxy'] = options['proxy']
    #     options['proxy'] = None
    # elif options['proxy'] and options['proxy'].startswith('i2p'):
    #     logger.info('Using I2P proxy')
    #     options['i2p_proxy'] = options['proxy']
    #     options['proxy'] = None

    # if options['proxy']:
    #     logger.info(f"Using proxy {options['proxy']}")
    #     await debug_ip_request(options['checkers']['http'], logger)

    # if options['tor_proxy']:
    #     await debug_ip_request(options['checkers']['tor'], logger)

    # if options['i2p_proxy']:
    #     await debug_ip_request(options['checkers']['i2p'], logger)

    # if options['cookies']:
    #     options['cookie_jar'] = import_aiohttp_cookies(options['cookies'])

    sites_total_count = len(site_dict)

    # Create a progress bar
    if not options['silent']:
        query_notify.bar = alive_bar(
            sites_total_count,
            title='Searching',
            force_tty=True,
            enrich_print=False,
        )

    query_notify.sites_count = sites_total_count

    # TODO: add another executor for retries
    executor = AsyncioQueueGeneratorExecutor(
        check_site_for_username,
        logger=logger,
        max_workers=options['max_connections'],
    )

    all_results = {}

    def get_results_from_future(future):
        name, result = future.result()
        all_results[name] = result
        # if not options['silent']:
        #     query_notify.bar()

    tasks = []
    for site in site_dict.values():
        task = executor.submit(site, username, options, logger, query_notify)
        task.add_done_callback(get_results_from_future)
        tasks.append(task)

    await asyncio.gather(*tasks)

    # if options['retries'] > 0:
    #     failed_sites = get_failed_sites(all_results)
    #     retries_count = options['retries']
    #     logger.info(f'Retrying {len(failed_sites)} sites, {retries_count} retries left')
    #     options['retries'] = retries_count - 1
    #     retry_results = await maigret(
    #         username=username,
    #         site_dict={k:v for k,v in site_dict.items() if k in failed_sites},
    #         logger=logger,
    #         query_notify=query_notify,
    #         **options
    #     )
    #     all_results.update(retry_results)

    # if not options['silent']:
    #     query_notify.bar.title = 'Finished'

    return all_results

# ... (rest of the code remains the same)
