from form_spam_guard import ContentFilter, DEFAULT_BLOCKED_HOSTS

# "Vam perevod 193155 rub. zabrat tut https://5d58cc63.sslip.io/x" in Cyrillic
SPAM = (
    "\u0412\u0430\u043c \u043f\u0435\u0440\u0435\u0432\u043e\u0434 193155 "
    "\u0440\u0443\u0431. \u0437\u0430\u0431\u0440\u0430\u0442\u044c \u0442\u0443\u0442 "
    "https://5d58cc63.sslip.io/x"
)
FRENCH = (
    "Bonjour, je m'appelle H\u00e9l\u00e8ne Th\u00e9riault et je voudrais une soumission "
    "pour un g\u00e2teau de mariage \u00e0 Miramichi. Merci beaucoup, \u00e0 bient\u00f4t!"
)
ENGLISH = "Hi, I would like a quote for a new website for my small business. Please call me."


def test_spam_sample_blocked_for_foreign_script():
    f = ContentFilter(allowed_scripts=["latin"], max_links=5)
    reasons = [x.reason for x in f.findings(SPAM)]
    assert "foreign_script" in reasons


def test_spam_sample_blocked_for_link_host():
    f = ContentFilter(check_scripts=False)
    finding = f.check(SPAM)
    assert finding is not None
    assert finding.reason == "blocked_link_host"
    assert finding.detail == "5d58cc63.sslip.io"


def test_spam_sample_reports_both_reasons():
    reasons = [x.reason for x in ContentFilter().findings(SPAM)]
    assert reasons[:2] == ["foreign_script", "blocked_link_host"]


def test_french_names_with_accents_pass():
    assert ContentFilter().check(FRENCH) is None


def test_english_enquiry_passes():
    assert ContentFilter().check(ENGLISH) is None


def test_link_to_customer_site_passes():
    text = "Hello, I saw your work for https://boulangerie-leblanc.ca and want the same."
    f = ContentFilter(allowed_domains=["boulangerie-leblanc.ca"])
    assert f.check(text) is None


def test_allowed_domain_matches_subdomains_and_www():
    f = ContentFilter(allowed_domains=["example.ca"], max_links=0)
    assert f.check("see www.example.ca and https://shop.example.ca/x") is None


def test_allowed_domain_does_not_match_lookalike():
    f = ContentFilter(allowed_domains=["example.ca"], max_links=0)
    finding = f.check("see https://notexample.ca/")
    assert finding is not None and finding.reason == "too_many_links"


def test_allowlisted_link_can_override_blocked_host():
    f = ContentFilter(allowed_domains=["bit.ly"])
    assert f.check("our short link https://bit.ly/abc") is None


def test_suffix_matching_for_wildcard_hosts():
    f = ContentFilter()
    for url in (
        "http://a.b.sslip.io/x",
        "https://1-2-3-4.nip.io",
        "https://abcd.ngrok-free.app/login",
        "https://foo.trycloudflare.com",
        "https://bit.ly/3xyz",
        "https://t.me/somebody",
        "https://telegra.ph/x-01-01",
    ):
        finding = f.check("please look " + url)
        assert finding is not None and finding.reason == "blocked_link_host", url


def test_lookalike_host_is_not_blocked():
    f = ContentFilter()
    assert f.check("visit https://notbit.ly.example.com and https://mysslip.io.ca") is None


def test_bare_blocked_host_without_scheme():
    finding = ContentFilter().check("go to bit.ly/abc now")
    assert finding is not None and finding.reason == "blocked_link_host"


def test_plain_prose_is_not_a_link():
    assert ContentFilter().check("Prices are e.g. 5.00 or Mr.Smith said hi.") is None


def test_extensible_blocklist():
    f = ContentFilter(blocked_hosts=["evil.example"])
    finding = f.check("see https://x.evil.example/p")
    assert finding is not None and finding.reason == "blocked_link_host"
    assert "sslip.io" in f.blocked_hosts


def test_default_list_contains_required_hosts():
    required = {
        "sslip.io", "nip.io", "xip.io", "ngrok.io", "ngrok-free.app",
        "trycloudflare.com", "loca.lt", "bit.ly", "tinyurl.com", "t.me",
        "telegra.ph", "cutt.ly", "is.gd",
    }
    assert required <= set(DEFAULT_BLOCKED_HOSTS)


def test_too_many_links():
    f = ContentFilter(max_links=2)
    ok = "https://a.example.com and https://b.example.com"
    bad = ok + " and https://c.example.com"
    assert f.check(ok) is None
    finding = f.check(bad)
    assert finding is not None and finding.reason == "too_many_links"


def test_allowlisted_links_do_not_count():
    f = ContentFilter(max_links=1, allowed_domains=["mine.ca"])
    assert f.check("https://mine.ca/a https://mine.ca/b https://mine.ca/c https://other.org") is None


def test_configurable_scripts():
    cyr = "\u041f\u0440\u0438\u0432\u0435\u0442, \u043a\u0430\u043a \u0434\u0435\u043b\u0430 \u0434\u0440\u0443\u0433"
    assert ContentFilter(allowed_scripts=["latin"]).check(cyr) is not None
    assert ContentFilter(allowed_scripts=["latin", "cyrillic"]).check(cyr) is None


def test_cjk_and_arabic_rejected_on_latin_site():
    cjk = "\u4f60\u597d\uff0c\u6211\u60f3\u4e70\u4f60\u4eec\u7684\u4ea7\u54c1"
    arabic = "\u0645\u0631\u062d\u0628\u0627 \u0643\u064a\u0641 \u062d\u0627\u0644\u0643 \u0627\u0644\u064a\u0648\u0645"
    f = ContentFilter()
    assert f.check(cjk).reason == "foreign_script"
    assert f.check(arabic).reason == "foreign_script"
    assert ContentFilter(allowed_scripts=["chinese"]).check(cjk) is None


def test_threshold_allows_a_few_foreign_letters():
    text = "Thanks for the great cake, the word for cake is \u0442\u043e\u0440\u0442 in Russian."
    assert ContentFilter().check(text) is None
    assert ContentFilter(max_foreign_ratio=0.0).check(text).reason == "foreign_script"


def test_url_host_letters_do_not_count_as_text():
    f = ContentFilter(max_links=5)
    assert f.foreign_ratio("https://\u043f\u0440\u0438\u043c\u0435\u0440.example.com/ hello there") == 0.0


def test_very_short_text_is_not_judged_by_script():
    assert ContentFilter().check("\u0434\u0430") is None
