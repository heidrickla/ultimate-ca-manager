"""Regression tests: XSS in the public /acme/terms page.

The server-side renderer escaped only ``& < >`` before interpolating
autolinked URLs into a double-quoted ``href`` attribute, and its URL
character class admitted ``"`` — the same missing-quote-escape flaw the
admin ToS preview had (PR #247). A quote inside a stored ToS URL therefore
broke out of the attribute and injected arbitrary attributes (for example
``onmouseover``) into an unauthenticated, public page.

The body is admin-supplied via the ACME settings, so this is defence in
depth against a hostile or compromised operator account, mirroring the
frontend fix.
"""
import json
from html.parser import HTMLParser

import pytest


TOS_KEY = 'acme.terms_of_service'


class _AttrCollector(HTMLParser):
    """Collect every (tag, attribute-name) pair in a document."""

    def __init__(self):
        super().__init__()
        self.attrs = []

    def handle_starttag(self, tag, attrs):
        for name, _ in attrs:
            self.attrs.append((tag, name.lower()))


def _set_tos(app, body, title='Terms'):
    from models import db, SystemConfig
    with app.app_context():
        row = SystemConfig.query.filter_by(key=TOS_KEY).first()
        value = json.dumps({'title': title, 'body': body})
        if row:
            row.value = value
        else:
            db.session.add(SystemConfig(key=TOS_KEY, value=value))
        db.session.commit()


@pytest.fixture(autouse=True)
def _clean_tos(app):
    yield
    from models import db, SystemConfig
    with app.app_context():
        SystemConfig.query.filter_by(key=TOS_KEY).delete()
        db.session.commit()


def _page_attrs(client):
    r = client.get('/acme/terms')
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    parser = _AttrCollector()
    parser.feed(html)
    return html, parser.attrs


def test_quote_in_url_cannot_break_out_of_href(app, client):
    _set_tos(app, 'Read https://a"onmouseover=alert(1)//x first')
    html, attrs = _page_attrs(client)
    # No element anywhere in the page may carry an event-handler attribute.
    for tag, name in attrs:
        assert not name.startswith('on'), f'injected attribute {name} on <{tag}>'
    # The quote survives only in escaped form.
    assert '&quot;' in html


def test_quote_in_plain_text_is_escaped(app, client):
    _set_tos(app, 'A "quoted" sentence with no URL.')
    html, attrs = _page_attrs(client)
    for tag, name in attrs:
        assert not name.startswith('on'), f'injected attribute {name} on <{tag}>'
    assert '&quot;quoted&quot;' in html


def test_html_in_body_stays_inert(app, client):
    _set_tos(app, '<img src=x onerror=alert(1)> and <script>alert(2)</script>')
    html, attrs = _page_attrs(client)
    tags = {tag for tag, _ in attrs}
    assert 'img' not in tags
    assert '<script>alert' not in html
    assert '&lt;script&gt;' in html


def test_legitimate_url_still_autolinks(app, client):
    _set_tos(app, 'See https://example.com/tos for details.\n\nSecond paragraph.')
    html, _ = _page_attrs(client)
    assert '<a href="https://example.com/tos"' in html
    assert 'rel="noopener"' in html
    # Paragraph split still works.
    assert html.count('<p>') == 2


# --- Regression (#247 self-review): quote-escaping runs BEFORE autolinking,
# and the entity forms (&quot; &#x27;) are built entirely of URL-legal
# characters, so the URL pattern swallowed them into the href. The browser
# then decoded the entity inside the attribute VALUE, producing a link to
# https://example.com/tos" — a 404 — for the perfectly ordinary ToS body
# `Please read "https://example.com/tos" carefully.`


def test_double_quoted_url_links_to_the_bare_url(app, client):
    _set_tos(app, 'Please read "https://example.com/tos" carefully.')
    html, attrs = _page_attrs(client)
    # The href is exactly the URL — no swallowed &quot;.
    assert '<a href="https://example.com/tos"' in html
    # The quotes survive, escaped, OUTSIDE the anchor.
    assert '&quot;<a href="https://example.com/tos"' in html
    assert '</a>&quot; carefully.' in html
    # And the original security property still holds: no attribute breakout.
    for tag, name in attrs:
        assert not name.startswith('on'), f'injected attribute {name} on <{tag}>'


def test_single_quoted_url_links_to_the_bare_url(app, client):
    _set_tos(app, "See 'https://example.com/tos' for details.")
    html, attrs = _page_attrs(client)
    assert '<a href="https://example.com/tos"' in html
    assert '</a>&#x27; for details.' in html
    for tag, name in attrs:
        assert not name.startswith('on'), f'injected attribute {name} on <{tag}>'


def test_angle_bracketed_url_links_to_the_bare_url(app, client):
    # Pre-dates the quote escaping: < > were always escaped before
    # autolinking, so <https://...> swallowed &gt; the same way.
    _set_tos(app, 'Wrapped <https://example.com/tos> here.')
    html, _ = _page_attrs(client)
    assert '<a href="https://example.com/tos"' in html
    assert '</a>&gt; here.' in html


def test_trailing_sentence_punctuation_stays_out_of_href(app, client):
    _set_tos(app, 'Read https://example.com/tos. Then https://example.com/faq, ok?')
    html, _ = _page_attrs(client)
    assert '<a href="https://example.com/tos"' in html
    assert '</a>. Then' in html
    assert '<a href="https://example.com/faq"' in html
    assert '</a>, ok?' in html


def test_url_ending_in_permitted_characters_keeps_them(app, client):
    # Trimming must not eat legitimate URL endings: a trailing slash, a
    # query string (whose & is escaped to &amp; INSIDE the href), or a
    # trailing & itself.
    _set_tos(app, 'Use https://example.com/v2/ or https://example.com/s?q=a&b=2 '
                  'or even https://example.com/?a=1& today')
    html, _ = _page_attrs(client)
    assert '<a href="https://example.com/v2/"' in html
    assert '<a href="https://example.com/s?q=a&amp;b=2"' in html
    assert '<a href="https://example.com/?a=1&amp;"' in html


def test_quoted_attack_url_still_cannot_break_out(app, client):
    # The regression fix must not reintroduce the original vulnerability:
    # the quote is trimmed off the href, never left raw inside it.
    _set_tos(app, 'x "https://a" onmouseover="alert(1)" y')
    html, attrs = _page_attrs(client)
    for tag, name in attrs:
        assert not name.startswith('on'), f'injected attribute {name} on <{tag}>'
    assert '<a href="https://a"' in html
    assert 'onmouseover=&quot;alert(1)&quot;' in html
