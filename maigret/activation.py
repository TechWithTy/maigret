import json
from http.cookiejar import MozillaCookieJar
from http.cookies import Morsel

from aiohttp import ClientSession, CookieJar


class ParsingActivator:
    def __init__(self, session: ClientSession):
        self.session = session

    async def twitter(self, site, logger, cookies={}):
        headers = dict(site.headers)
        if 'x-guest-token' in headers:
            del headers["x-guest-token"]

        async with self.session.post(site.activation["url"], headers=headers) as r:
            logger.info(r)
            j = await r.json()
            guest_token = j[site.activation["src"]]
            site.headers["x-guest-token"] = guest_token

    async def vimeo(self, site, logger, cookies={}):
        headers = dict(site.headers)
        if "Authorization" in headers:
            del headers["Authorization"]

        async with self.session.get(site.activation["url"], headers=headers) as r:
            resp_json = await r.json()
            logger.debug(f"Vimeo viewer activation: {json.dumps(resp_json, indent=4)}")
            jwt_token = resp_json["jwt"]
            site.headers["Authorization"] = "jwt " + jwt_token

    async def spotify(self, site, logger, cookies={}):
        headers = dict(site.headers)
        if "Authorization" in headers:
            del headers["Authorization"]

        async with self.session.get(site.activation["url"]) as r:
            bearer_token = (await r.json())["accessToken"]
            site.headers["authorization"] = f"Bearer {bearer_token}"

    async def weibo(self, site, logger):
        headers = dict(site.headers)
        # 1 stage: get the redirect URL
        async with self.session.get(
            "https://weibo.com/clairekuo", headers=headers, allow_redirects=False
        ) as r:
            logger.debug(
                f"1 stage: {'success' if r.status == 302 else 'no 302 redirect, fail!'}"
            )
            location = r.headers.get("Location")

        # 2 stage: go to passport visitor page
        headers["Referer"] = location
        async with self.session.get(location, headers=headers) as r:
            logger.debug(
                f"2 stage: {'success' if r.status == 200 else 'no 200 response, fail!'}"
            )

        # 3 stage: gen visitor token
        headers["Referer"] = location
        async with self.session.post(
            "https://passport.weibo.com/visitor/genvisitor2",
            headers=headers,
            data={'cb': 'visitor_gray_callback', 'tid': '', 'from': 'weibo'},
        ) as r:
            cookies = r.headers.get('set-cookie')
            logger.debug(
                f"3 stage: {'success' if r.status == 200 and cookies else 'no 200 response and cookies, fail!'}"
            )
            site.headers["Cookie"] = cookies


def import_aiohttp_cookies(cookiestxt_filename):
    cookies_obj = MozillaCookieJar(cookiestxt_filename)
    cookies_obj.load(ignore_discard=True, ignore_expires=True)

    cookies = CookieJar()

    cookies_list = []
    for domain in cookies_obj._cookies.values():
        for key, cookie in list(domain.values())[0].items():
            c = Morsel()
            c.set(key, cookie.value, cookie.value)
            c["domain"] = cookie.domain
            c["path"] = cookie.path
            cookies_list.append((key, c))

    cookies.update_cookies(cookies_list)

    return cookies
