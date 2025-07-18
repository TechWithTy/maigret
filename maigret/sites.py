# ****************************** -*-
# -*- coding: utf-8 -*-
"""Maigret Sites Information"""
import copy
import json
import sys
import aiofiles
import aiohttp
from typing import Optional, List, Dict, Any, Tuple

from .utils import CaseConverter, URLMatcher, is_country_tag


class MaigretEngine:
    """Class for a Maigret engine"""
    site: Dict[str, Any] = {}

    def __init__(self, name, data):
        self.name = name
        self.site = data

    @property
    def json(self):
        """Get engine data as a dictionary"""
        return self.site


class MaigretSite:
    """Class for a Maigret site"""
    # Fields that should not be serialized when converting site to JSON
    NOT_SERIALIZABLE_FIELDS = [
        "name",
        "engineData",
        "requestFuture",
        "detectedEngine",
        "engineObj",
        "stats",
        "urlRegexp",
    ]

    # Username known to exist on the site
    username_claimed = ""
    # Username known to not exist on the site
    username_unclaimed = ""
    # Additional URL path component, e.g. /forum in https://example.com/forum/users/{username}
    url_subpath = ""
    # Main site URL (the main page)
    url_main = ""
    # Full URL pattern for username page, e.g. https://example.com/forum/users/{username}
    url = ""
    # Whether site is disabled. Not used by Maigret without --use-disabled argument
    disabled = False
    # Whether a positive result indicates accounts with similar usernames rather than exact matches
    similar_search = False
    # Whether to ignore 403 status codes
    ignore403 = False
    # Site category tags
    tags: List[str] = []

    # Type of identifier (username, gaia_id etc); see SUPPORTED_IDS in checking.py
    type = "username"
    # Custom HTTP headers
    headers: Dict[str, str] = {}
    # Error message substrings
    errors: Dict[str, str] = {}
    # Site activation requirements
    activation: Dict[str, Any] = {}
    # Regular expression for username validation
    regex_check = None
    # URL to probe site status
    url_probe = None
    # Type of check to perform
    check_type = ""
    # Whether to only send HEAD requests (GET by default)
    request_head_only = ""
    # GET parameters to include in requests
    get_params: Dict[str, Any] = {}

    # Substrings in HTML response that indicate profile exists
    presense_strs: List[str] = []
    # Substrings in HTML response that indicate profile doesn't exist
    absence_strs: List[str] = []
    # Site statistics
    stats: Dict[str, Any] = {}

    # Site engine name
    engine = None
    # Engine-specific configuration
    engine_data: Dict[str, Any] = {}
    # Engine instance
    engine_obj: Optional["MaigretEngine"] = None
    # Future for async requests
    request_future = None
    # Alexa traffic rank
    alexa_rank = None
    # Source (in case a site is a mirror of another site)
    source = None

    # URL protocol (http/https)
    protocol = ''

    def __init__(self, name, information):
        self.name = name
        # Set default for mutable fields
        self.tags = []
        self.headers = {}
        self.errors = {}
        self.activation = {}
        self.get_params = {}
        self.presense_strs = []
        self.absence_strs = []
        self.stats = {}
        self.engine_data = {}
        
        self.url_subpath = ""

        for k, v in information.items():
            self.__dict__[CaseConverter.camel_to_snake(k)] = v

        if (self.alexa_rank is None) or (self.alexa_rank == 0):
            # We do not know the popularity, so make site go to bottom of list.
            self.alexa_rank = sys.maxsize

        self.update_detectors()

    def __str__(self):
        return f"{self.name} ({self.url_main})"

    def __is_equal_by_url_or_name(self, url_or_name_str: str):
        lower_url_or_name_str = url_or_name_str.lower()
        lower_url = str(self.url).lower()
        lower_name = self.name.lower()
        lower_url_main = str(self.url_main).lower()

        return (
            lower_name == lower_url_or_name_str
            or (lower_url_main and lower_url_main == lower_url_or_name_str)
            or (lower_url_main and lower_url_main in lower_url_or_name_str)
            or (lower_url_main and lower_url_or_name_str in lower_url_main)
            or (lower_url and lower_url_or_name_str in lower_url)
        )

    def __eq__(self, other):
        if isinstance(other, MaigretSite):
            # Compare only relevant attributes, not internal state like request_future
            attrs_to_compare = [
                'name',
                'url_main',
                'url_subpath',
                'type',
                'headers',
                'errors',
                'activation',
                'regex_check',
                'url_probe',
                'check_type',
                'request_head_only',
                'get_params',
                'presense_strs',
                'absence_strs',
                'stats',
                'engine',
                'engine_data',
                'alexa_rank',
                'source',
                'protocol',
            ]

            return all(
                getattr(self, attr, None) == getattr(other, attr, None) for attr in attrs_to_compare
            )
        elif isinstance(other, str):
            # Compare only by name (exactly) or url_main (partial similarity)
            return self.__is_equal_by_url_or_name(other)
        return False

    def update_detectors(self):
        """Update URL detectors"""
        if "url" in self.__dict__ and isinstance(self.url, str):
            url = self.url
            for group in ["urlMain", "urlSubpath"]:
                snake_group = CaseConverter.camel_to_snake(group)
                if "{" + group + "}" in url:
                    url = url.replace(
                        "{" + group + "}",
                        self.__dict__.get(snake_group, ""),
                    )

            self.url_regexp = URLMatcher.make_profile_url_regexp(url, self.regex_check)

    def detect_username(self, url: str) -> Optional[str]:
        """Detect username from a URL"""
        if hasattr(self, "url_regexp") and self.url_regexp:
            match_groups = self.url_regexp.match(url)
            if match_groups:
                return match_groups.groups()[-1].rstrip("/")

        return None

    def extract_id_from_url(self, url: str) -> Optional[Tuple[str, str]]:
        """
        Extracts username from url.
        """
        if not hasattr(self, "url_regexp") or not self.url_regexp:
            return None

        match_groups = self.url_regexp.match(url)
        if not match_groups:
            return None

        _id = match_groups.groups()[-1].rstrip("/")
        _type = self.type

        return _id, _type

    @property
    def pretty_name(self):
        """Get a pretty name for the site"""
        if self.source:
            return f"{self.name} [{self.source}]"
        return self.name

    @property
    def json(self):
        """Get site data as a dictionary"""
        result = {}
        for k, v in self.__dict__.items():
            # convert to camelCase
            field = CaseConverter.snake_to_camel(k)
            # strip empty elements
            if v in (False, "", [], {}, None, sys.maxsize, "username"):
                continue
            if field in self.NOT_SERIALIZABLE_FIELDS:
                continue
            result[field] = v

        return result

    @property
    def errors_dict(self) -> dict:
        """Get a dictionary of errors"""
        errors: Dict[str, str] = {}
        if self.engine_obj:
            errors.update(self.engine_obj.site.get('errors', {}))
        errors.update(self.errors)
        return errors

    def get_url_template(self) -> str:
        """Get a template for the URL"""
        url = URLMatcher.extract_main_part(self.url)
        if url.startswith("{username}"):
            url = "SUBDOMAIN"
        elif url == "":
            url = f"{self.url} ({self.engine or 'no engine'})"
        else:
            parts = url.split("/")
            url = "/" + "/".join(parts[1:])
        return url

    def update(self, updates: "dict") -> "MaigretSite":
        """Update site data"""
        self.__dict__.update(updates)
        self.update_detectors()

        return self

    def update_from_engine(self, engine: MaigretEngine) -> "MaigretSite":
        """Update site data from an engine"""
        engine_data = engine.site
        for k, v in engine_data.items():
            field = CaseConverter.camel_to_snake(k)
            if isinstance(v, dict):
                # update dicts like errors
                self.__dict__.setdefault(field, {}).update(v)
            elif isinstance(v, list):
                self.__dict__.setdefault(field, []).extend(v)
            else:
                self.__dict__[field] = v

        self.engine_obj = engine
        self.update_detectors()

        return self

    def strip_engine_data(self) -> "MaigretSite":
        """Strip engine data from site"""
        if not self.engine_obj:
            return self

        self.request_future = None
        self.url_regexp = None

        self_copy = copy.deepcopy(self)
        engine_data = self_copy.engine_obj.site if self_copy.engine_obj else {}
        site_data_keys = list(self_copy.__dict__.keys())

        for k in engine_data.keys():
            field = CaseConverter.camel_to_snake(k)
            is_exists = field in site_data_keys
            # remove dict keys
            if isinstance(engine_data.get(k), dict) and is_exists:
                for f in engine_data[k].keys():
                    if f in self_copy.__dict__[field]:
                        del self_copy.__dict__[field][f]
                continue
            # remove list items
            if isinstance(engine_data.get(k), list) and is_exists:
                for f in engine_data[k]:
                    if f in self_copy.__dict__[field]:
                        self_copy.__dict__[field].remove(f)
                continue
            if is_exists:
                del self_copy.__dict__[field]

        return self_copy


class MaigretDatabase:
    """Class for the Maigret database"""
    def __init__(self):
        self._tags: list = []
        self._sites: list = []
        self._engines: list = []

    @property
    def sites(self):
        """Get the list of sites"""
        return self._sites

    @property
    def sites_dict(self):
        """Get a dictionary of sites"""
        return {site.name: site for site in self._sites}

    def has_site(self, site: MaigretSite):
        """Check if a site exists in the database"""
        for s in self._sites:
            if site == s:
                return True
        return False

    def __contains__(self, site):
        return self.has_site(site)

    def ranked_sites_dict(
        self,
        reverse=False,
        top=sys.maxsize,
        tags=None,
        names=None,
        disabled=True,
        id_type="username",
    ):
        """
        Ranking and filtering of the sites list

        Args:
            reverse (bool, optional): Reverse the sorting order. Defaults to False.
            top (int, optional): Maximum number of sites to return. Defaults to sys.maxsize.
            tags (list, optional): List of tags to filter sites by. Defaults to empty list.
            names (list, optional): List of site names (or urls, see MaigretSite.__eq__) to filter by. Defaults to empty list.
            disabled (bool, optional): Whether to include disabled sites. Defaults to True.
            id_type (str, optional): Type of identifier to filter by. Defaults to "username".

        Returns:
            dict: Dictionary of filtered and ranked sites, with site names as keys and MaigretSite objects as values
        """
        if names is None:
            names = []
        if tags is None:
            tags = []

        normalized_names = list(map(str.lower, names))
        normalized_tags = list(map(str.lower, tags))

        is_name_ok = lambda x: x.name.lower() in normalized_names
        is_source_ok = lambda x: x.source and x.source.lower() in normalized_names
        is_engine_ok = (
            lambda x: isinstance(x.engine, str) and x.engine.lower() in normalized_tags
        )
        is_tags_ok = lambda x: set(map(str.lower, x.tags)).intersection(set(normalized_tags))
        is_protocol_in_tags = lambda x: x.protocol and x.protocol in normalized_tags
        is_disabled_needed = lambda x: not x.disabled or (
            "disabled" in tags or disabled
        )
        is_id_type_ok = lambda x: x.type == id_type

        filter_tags_engines_fun = (
            lambda x: not tags
            or is_engine_ok(x)
            or is_tags_ok(x)
            or is_protocol_in_tags(x)
        )
        filter_names_fun = lambda x: not names or is_name_ok(x) or is_source_ok(x)

        filter_fun = (
            lambda x: filter_tags_engines_fun(x)
            and filter_names_fun(x)
            and is_disabled_needed(x)
            and is_id_type_ok(x)
        )

        filtered_list = [s for s in self.sites if filter_fun(s)]

        sorted_list = sorted(
            filtered_list, key=lambda x: x.alexa_rank, reverse=reverse
        )[:top]
        return {site.name: site for site in sorted_list}

    @property
    def engines(self):
        """Get the list of engines"""
        return self._engines

    @property
    def engines_dict(self):
        """Get a dictionary of engines"""
        return {engine.name: engine for engine in self._engines}

    def update_site(self, site: MaigretSite) -> "MaigretDatabase":
        """Update a site in the database"""
        for i, s in enumerate(self._sites):
            if s.name == site.name:
                self._sites[i] = site
                return self

        self._sites.append(site)
        return self

    async def save_to_file(self, filename: str) -> "MaigretDatabase":
        """Save the database to a file"""
        if '://' in filename:
            return self

        db_data = {
            "sites": {site.name: site.strip_engine_data().json for site in self._sites},
            "engines": {engine.name: engine.json for engine in self._engines},
            "tags": self._tags,
        }

        json_data = json.dumps(db_data, indent=4, sort_keys=True)

        async with aiofiles.open(filename, "w", encoding="utf-8") as f:
            await f.write(json_data)

        return self

    async def load_from_path(self, path: str) -> "MaigretDatabase":
        """Load the database from a file path or URL"""
        if '://' in path:
            async with aiohttp.ClientSession() as session:
                async with session.get(path) as response:
                    response.raise_for_status()
                    json_data = await response.json()
        else:
            async with aiofiles.open(path, "r", encoding="utf-8") as f:
                content = await f.read()
                json_data = json.loads(content)

        return self.load_from_json(json_data)

    def load_from_json(self, json_data: dict) -> "MaigretDatabase":
        """Load the database from a dictionary"""
        site_data = json_data.get("sites", {})
        engines_data = json_data.get("engines", {})
        tags = json_data.get("tags", [])

        self._tags.extend(t for t in tags if t not in self._tags)

        for engine_name, engine_info in engines_data.items():
            self._engines.append(MaigretEngine(engine_name, engine_info))

        for site_name, site_info in site_data.items():
            try:
                maigret_site = MaigretSite(site_name, site_info)

                engine_name = site_info.get("engine")
                if engine_name and engine_name in self.engines_dict:
                    maigret_site.update_from_engine(self.engines_dict[engine_name])

                self.update_site(maigret_site)
            except KeyError as error:
                raise ValueError(
                    f"Problem parsing json content for site {site_name}: "
                    f"Missing attribute {str(error)}."
                ) from error

        return self

    def load_from_str(self, db_str: "str") -> "MaigretDatabase":
        """Load the database from a string"""
        try:
            data = json.loads(db_str)
        except json.JSONDecodeError as error:
            raise ValueError(
                f"Problem parsing json contents from str"
                f"'{db_str[:50]}...':  {str(error)}."
            ) from error

        return self.load_from_json(data)

    def get_scan_stats(self, sites_dict=None):
        """Get scan statistics"""
        sites = sites_dict or self.sites_dict
        found_flags = {}
        for _, s in sites.items():
            if "presense_flag" in s.stats:
                flag = s.stats["presense_flag"]
                found_flags[flag] = found_flags.get(flag, 0) + 1

        return found_flags

    def extract_ids_from_url(self, url: str) -> dict:
        """Extract IDs from a URL"""
        results = {}
        for s in self._sites:
            result = s.extract_id_from_url(url)
            if not result:
                continue
            _id, _type = result
            results[_id] = _type
        return results

    def get_db_stats(self, is_markdown=False):
        """Get database statistics"""
        sites_dict = self.sites_dict
        total_count = len(sites_dict)
        if total_count == 0:
            return "Database is empty."

        urls = {}
        tags = {}
        disabled_count = 0
        message_checks_one_factor = 0
        status_checks = 0

        for site in sites_dict.values():
            if site.disabled:
                disabled_count += 1

            url_type = site.get_url_template()
            urls[url_type] = urls.get(url_type, 0) + 1

            if not site.disabled:
                if site.check_type == 'message':
                    if not (site.absence_strs and site.presense_strs):
                        message_checks_one_factor += 1
                elif site.check_type == 'status_code':
                    status_checks += 1

            if not site.tags:
                tags["NO_TAGS"] = tags.get("NO_TAGS", 0) + 1
            for tag in filter(lambda x: not is_country_tag(x), site.tags):
                tags[tag] = tags.get(tag, 0) + 1

        enabled_count = total_count - disabled_count
        enabled_perc = round(100 * enabled_count / total_count, 2)
        checks_perc = round(100 * message_checks_one_factor / enabled_count, 2) if enabled_count else 0
        status_checks_perc = round(100 * status_checks / enabled_count, 2) if enabled_count else 0

        site_with_probing = [f"{s.name}{' (disabled)' if s.disabled else ''}" for s in sites_dict.values() if s.url_probe]
        site_with_activation = [f"{s.name}{' (disabled)' if s.disabled else ''}" for s in sites_dict.values() if s.activation]

        separator = "\n\n"
        output = [
            f"Enabled/total sites: {enabled_count}/{total_count} = {enabled_perc}%",
            f"Incomplete message checks: {message_checks_one_factor}/{enabled_count} = {checks_perc}% (false positive risks)",
            f"Status code checks: {status_checks}/{enabled_count} = {status_checks_perc}% (false positive risks)",
            f"False positive risk (total): {checks_perc + status_checks_perc:.2f}%",
            f"Sites with probing: {', '.join(sorted(site_with_probing))}",
            f"Sites with activation: {', '.join(sorted(site_with_activation))}",
            self._format_top_items("profile URLs", urls, 20, is_markdown),
            self._format_top_items("tags", tags, 20, is_markdown, self._tags),
        ]

        return separator.join(output)

    def _format_top_items(
        self, title, items_dict, limit, is_markdown, valid_items=None
    ):
        """Helper method to format top items lists"""
        if valid_items is None:
            valid_items = []
            
        output = f"Top {limit} {title}:\n"
        
        sorted_items = sorted(items_dict.items(), key=lambda x: x[1], reverse=True)

        for item, count in sorted_items[:limit]:
            if count == 1 and len(sorted_items) > limit:
                break
            mark = (
                " (non-standard)"
                if valid_items and item not in valid_items and item != "NO_TAGS"
                else ""
            )
            if is_markdown:
                output += f"- ({count})\t`{item}`{mark}\n"
            else:
                output += f"{count}\t{item}{mark}\n"
        return output