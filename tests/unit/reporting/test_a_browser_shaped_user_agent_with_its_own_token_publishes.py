"""A browser-shaped user agent that carries a token the browsers do not send is no browser's.

A bound user agent that begins as the common browsers' do used to stay
unpublished whatever followed the prefix, so one whose comment carried a
token of its own (an otherwise Internet Explorer shaped header with one more
entry) reached no surface. Now the header is read as its grammar (products
and comments) and each product name and comment word is asked against the
vocabulary the argument-role table lists for the browsers, their engines and
platforms: one outside it is the distinctive token, the value is published and
the reason names it. A header that cannot be read as that grammar, or that
does not begin as a browser's, keeps today's answer, and so does one whose
only token of its own is a well-known crawler's (with its info URL): an
indicator on it would match that crawler. Every distinctive token here is
invented.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from maljan.reporting.call_bindings import (
    browser_user_agent_tokens,
    distinctive_user_agent_token,
    reads_as_a_browser_user_agent,
)
from tests.linear_cost import assert_scales

ROOT = Path(__file__).resolve().parents[3]

_CHROME = "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0"

# Real browsers' headers, across engines, platforms and eras, with their versions.
BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36 OPR/105.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/70.0.3538.102 Safari/537.36 Edge/18.19582",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "CriOS/119.0.6045.169 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) "
    "SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; "
    ".NET CLR 2.0.50727; .NET CLR 3.5.30729; Media Center PC 6.0; InfoPath.2; .NET4.0C)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",
    "Opera/9.80 (Windows NT 6.1; U; en) Presto/2.12.388 Version/12.16",
    "Opera/9.80 (X11; Linux i686; U; en-US) Presto/2.9.168 Version/11.50",
    "Opera/9.80 (Windows NT 6.1; U; ru) Presto/2.12.388 Version/12.16",
    "Mozilla/5.0 (Linux; U; Android 4.4.2; en-us; SM-G900F Build/KOT49H) AppleWebKit/534.30 "
    "(KHTML, like Gecko) Version/4.0 Mobile Safari/534.30",
    "Mozilla/5.0 (Linux; Android 10; K; wv) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Version/4.0 Chrome/120.0.6099.43 Mobile Safari/537.36",
    # In-app, embedded and less common mainstream browsers.
    f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) {_CHROME} YaBrowser/24.1.0.0 Yowser/2.5 "
    "Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) GSA/300.0.598994205 Mobile/15E148 Safari/604.1",
    f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) {_CHROME} Electron/28.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.1 Safari/605.1.15 DuckDuckGo/7",
    f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) {_CHROME} Whale/3.24.223.18 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; Quest 3) AppleWebKit/537.36 (KHTML, like Gecko) "
    "OculusBrowser/30.0 Chrome/118.0.5993.80 VR Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0 "
    "SeaMonkey/2.53.18",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0 "
    "Waterfox/G6.0.5",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Goanna/6.5 "
    "Firefox/102.0 PaleMoon/32.5.0",
    f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) {_CHROME} Safari/537.36 Vivaldi/6.5.3206.48",
    "Mozilla/5.0 (Linux; U; Android 13; en-US; SM-A536B) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Version/4.0 Chrome/100.0.4896.58 UCBrowser/13.6.0.1315 "
    "Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; 2201117TG) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/112.0.5615.136 Mobile Safari/537.36 XiaoMi/MiuiBrowser/17.8.120717",
    "Mozilla/5.0 (Linux; Android 10; HarmonyOS; ELS-AN00) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Version/4.0 Chrome/99.0.4844.88 HuaweiBrowser/14.0.0.322 "
    "Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 9; KFTRWI) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Silk/120.4.1 like Chrome/120.0.6099.230 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/88.0.4324.150 Safari/537.36 Puffin/9.0.0.50263AP",
    f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) {_CHROME} Safari/537.36 Maxthon/7.1.6.1000",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/94.0.4606.71 Safari/537.36 Core/1.94.202.400 QQBrowser/12.0.0.0",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Mobile Safari/537.36 EdgA/120.0.2210.84",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 EdgiOS/120.2210.79 Mobile/15E148 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) FxiOS/121.0 Mobile/15E148 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Mobile Safari/537.36 OPT/4.4.0",
    "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0 Focus/121.0",
    # The Internet Explorer era's toolbar, runtime, OEM and device words.
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; GTB7.5; OfficeLiveConnector.1.3; "
    "OfficeLivePatch.0.0)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; BOIE9;ENUS)",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0; Touch; MASMJS)",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0; NP08)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; Zune 4.7; MS-RTC LM 8; AS)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox One) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/48.0.2564.82 Safari/537.36 Edge/14.14393",
]

# Well-known crawlers' headers: their own token, with or without the info URL after it.
CRAWLERS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    "Mozilla/5.0 (compatible; DuckDuckBot-Https/1.1; https://duckduckgo.com/duckduckbot)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/13.1.1 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)",
    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.6099.71 Mobile Safari/537.36 "
    "(compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]


@pytest.mark.parametrize("agent", BROWSERS)
def test_a_real_browser_header_stays_a_browser_s(agent: str) -> None:
    assert distinctive_user_agent_token(agent) == ""
    assert reads_as_a_browser_user_agent(agent)


@pytest.mark.parametrize(
    ("agent", "token"),
    [
        # The shape the defect was found in: one more comment entry after the platform.
        ("Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Tob 1.1)", "Tob 1.1"),
        ("Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; Pexel)", "Pexel"),
        ("Mozilla/5.0 (Windows NT 6.1; zzq-loader)", "zzq-loader"),
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) unit", "unit"),
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36 Varnu/3.2",
            "Varnu/3.2",
        ),
        ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; Krell)", "Krell"),
        ("Opera/9.80 (Windows NT 6.1; U; en) Presto/2.12.388 Brisk", "Brisk"),
    ],
)
def test_a_token_the_browsers_do_not_send_is_named(agent: str, token: str) -> None:
    assert distinctive_user_agent_token(agent) == token
    assert not reads_as_a_browser_user_agent(agent)


@pytest.mark.parametrize("agent", CRAWLERS)
def test_a_well_known_crawler_s_header_stays_unpublished(agent: str) -> None:
    assert distinctive_user_agent_token(agent) == ""
    assert reads_as_a_browser_user_agent(agent)


@pytest.mark.parametrize(
    ("agent", "token"),
    [
        # An info URL is read past only right after a crawler's own token, and at its domain.
        ("Mozilla/5.0 (compatible; +http://relay.example/x)", "+http://relay.example/x"),
        ("Mozilla/5.0 (Windows NT 10.0; +http://relay.example/x)", "+http://relay.example/x"),
        (
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://relay.example/bot.html)",
            "+http://relay.example/bot.html",
        ),
        (
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://google.com.relay.example/x)",
            "+http://google.com.relay.example/x",
        ),
        (
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.google.com/bot.html)",
            "+http://www.google.com/bot.html",
        ),
        ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://a; Tob)", "+http://a"),
        # A crawler is its own name, alone or with its version, and nothing more.
        ("Mozilla/5.0 (compatible; Googlebot/Tob; +http://x)", "Googlebot/Tob"),
        ("Mozilla/5.0 (compatible; Googlebot/2.1 1evil; +http://x)", "Googlebot/2.1 1evil"),
        ("Mozilla/5.0 (compatible; Googlebot 2.1 7zip)", "Googlebot 2.1 7zip"),
        ("Mozilla/5.0 (compatible; Googlebot/2.1) Tob/1", "Tob/1"),
        # A crawler's token does not hide another token beside it.
        (
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html; Tob 1.1)",
            "Tob 1.1",
        ),
    ],
)
def test_beside_a_crawler_or_alone_a_token_is_still_named(agent: str, token: str) -> None:
    assert distinctive_user_agent_token(agent) == token


@pytest.mark.parametrize(
    ("agent", "token"),
    [
        # A word's tail after '/' or ':' is read past only when it is a version.
        ("Mozilla/5.0 (Windows/Tob)", "Windows/Tob"),
        ("Mozilla/5.0 (Windows NT 10.0; rv:evil) Gecko/20100101 Firefox/121.0", "rv:evil"),
        ("Mozilla/5.0 (Windows NT 10.0; Trident/x7) like Gecko", "Trident/x7"),
        ("Mozilla/5.0 (Windows NT 6.1; Windows/1evil)", "Windows/1evil"),
        ("Mozilla/5.0 (Windows NT 6.1; rv:1evil)", "rv:1evil"),
        ("Mozilla/5.0 (Windows NT 6.1; rv:2.0b)", "rv:2.0b"),
        # A word that begins with a digit is read past only as a version or a build.
        ("Mozilla/5.0 (Windows NT 10.0; 12ab34cd)", "12ab34cd"),
        ("Mozilla/5.0 (Windows NT 10.0; 7-zz)", "7-zz"),
        ("Mozilla/5.0 (Windows NT 6.1; 7zip)", "7zip"),
        ("Mozilla/5.0 (Windows NT 6.1; 5a)", "5a"),
        ("Mozilla/5.0 (Windows NT 6.1; 1Tob2)", "1Tob2"),
        ("Mozilla/5.0 (Windows NT 6.1; 1evil)", "1evil"),
        ("Mozilla/5.0 (Windows NT 6.1; 15e148)", "15e148"),
        # A word a browser sends only beside its own, or right after its own.
        ("Mozilla/5.0 (Windows NT 6.1) Core/1.0", "Core/1.0"),
        ("Mozilla/5.0 (Windows NT 6.1) VR/1.0", "VR/1.0"),
        ("Mozilla/5.0 (Windows NT 6.1; One)", "One"),
        ("Mozilla/5.0 (Windows NT 6.1; Xbox; One)", "One"),
        ("Mozilla/5.0 (Windows NT 6.1; Xbox; Xbox One; Tob)", "Tob"),
        ("Mozilla/5.0 (Windows NT 6.1; NP)", "NP"),
        ("Mozilla/5.0 (Windows NT 6.1; NP3)", "NP3"),
        # A two-letter word only as a listed language code, a locale or a listed word.
        ("Mozilla/5.0 (Windows NT 10.0; zz)", "zz"),
        ("Mozilla/5.0 (Windows NT 10.0; QX)", "QX"),
        ("Opera/9.80 (Windows NT 6.1; U; en-USA) Presto/2.12.388", "en-USA"),
    ],
)
def test_a_word_is_read_past_only_in_the_shape_the_vocabulary_states(
    agent: str, token: str
) -> None:
    assert distinctive_user_agent_token(agent) == token


def test_a_token_after_android_is_read_past_a_known_false_negative() -> None:
    # The entries after 'Android' name the device, which no vocabulary lists.
    agent = "Mozilla/5.0 (Linux; Android 10; Tob 1.1) AppleWebKit/537.36 (KHTML, like Gecko)"

    assert distinctive_user_agent_token(agent) == ""


@pytest.mark.parametrize("word", ["to", "id", "is"])
def test_a_bare_language_code_is_read_past_a_known_false_negative(word: str) -> None:
    # Refusing it would publish real browsers' headers that carry their locale.
    assert distinctive_user_agent_token(f"Mozilla/5.0 (Windows NT 6.1; {word})") == ""


@pytest.mark.parametrize(
    "agent",
    [
        "Mozilla/5.0 (",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64",
        "Mozilla/5.0 (Windows (NT 10.0)) Tob/1",
        "Mozilla/5.0 (Windows NT 10.0; a\\b) Tob/1",
        'Mozilla/5.0 (Windows NT 10.0) "Tob"',
        "Mozilla/5.0 (Windows NT 10.0) Tob/1) x",
    ],
)
def test_a_header_that_is_not_its_grammar_stays_unpublished(agent: str) -> None:
    # Unreadable: today's conservative answer, a browser's.
    assert distinctive_user_agent_token(agent) == ""
    assert reads_as_a_browser_user_agent(agent)


@pytest.mark.parametrize("agent", ["", None, "ExampleAgent/2.1 (unit)", " Mozilla/5.0 (Tob)"])
def test_one_that_does_not_begin_as_a_browser_s_is_not_asked(agent: str | None) -> None:
    assert distinctive_user_agent_token(agent) == ""
    assert not reads_as_a_browser_user_agent(agent)


def test_the_vocabulary_is_listed_with_its_source() -> None:
    document = json.loads((ROOT / "data" / "api_argument_roles_v1.json").read_text())
    listed = document["browser_user_agents"]["tokens"]
    tokens = browser_user_agent_tokens()

    assert listed["source"]
    assert {"mozilla", "applewebkit", "chrome", "firefox", "safari"} <= tokens.products
    assert {"windows", "nt", "linux", "android", "macintosh", "rv"} <= tokens.words
    assert {"en", "ru"} <= tokens.languages and "zz" not in tokens.languages
    assert {"googlebot", "bingbot", "yahoo! slurp"} <= set(tokens.crawlers)
    assert all(tokens.crawlers.values())
    assert tokens.products_beside["core"] >= {"qqbrowser"}
    assert tokens.words_after["one"] == {"xbox"}
    assert not {"core", "vr"} & tokens.products and "one" not in tokens.words


@pytest.mark.parametrize(
    "build",
    [
        lambda n: "Mozilla/5.0 (" + "Windows NT 10.0; " * n + ")",
        lambda n: "Mozilla/5.0 (Windows NT 10.0) " + "Chrome/1.0 " * n,
        lambda n: "Mozilla/5.0 (" + "1" * n + "-",
        lambda n: "Mozilla/5.0 (x) " + "a" * n,
        lambda n: "Mozilla/5.0 (" + "1" * (n * 8) + "-x)",
        lambda n: "Mozilla/5.0 (" + "1" * (n * 8) + "a" * n + "!)",
        lambda n: "Mozilla/5.0 (" + "Googlebot/2.1; +http://www.google.com/bot; " * n + ")",
        lambda n: "Mozilla/5.0 (" + "Xbox One; " * n + ")",
        lambda n: "Mozilla/5.0 (Windows NT 10.0) Core/1 " + "QQBrowser/1 " * n,
        lambda n: "Mozilla/5.0 (rv:" + "1" * (n * 8) + "!)",
    ],
    ids=[
        "entries",
        "products",
        "unclosed",
        "one-product",
        "one-word",
        "build",
        "crawler",
        "after",
        "beside",
        "tail",
    ],
)
def test_reading_a_long_header_stays_linear(build: Callable[[int], str]) -> None:
    assert_scales(build, 5_000, distinctive_user_agent_token)
