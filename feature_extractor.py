from urllib.parse import urlparse
import ipaddress
import re


def extract_features(url):
    # Make sure the URL has a scheme
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    # Basic URL information
    url_length = len(url)

    domain = parsed.netloc.split("@")[-1].split(":")[0]
    domain_length = len(parsed.netloc)

    # Check whether domain is an IP address
    try:
        ipaddress.ip_address(domain)
        is_domain_ip = 1
    except ValueError:
        is_domain_ip = 0

    # Count subdomains
    domain_parts = domain.split(".")
    no_of_subdomain = max(len(domain_parts) - 2, 0)

    # Character counts
    no_of_letters = sum(char.isalpha() for char in url)
    no_of_digits = sum(char.isdigit() for char in url)

    letter_ratio = no_of_letters / url_length if url_length else 0
    digit_ratio = no_of_digits / url_length if url_length else 0

    # URL symbols
    no_of_equals = url.count("=")
    no_of_qmark = url.count("?")
    no_of_ampersand = url.count("&")

    # Other special characters
    special_chars = sum(
        not char.isalnum() for char in url
    )

    special_char_ratio = special_chars / url_length if url_length else 0

    # Percent-encoded / obfuscated characters
    obfuscated_matches = re.findall(r"%[0-9a-fA-F]{2}", url)

    no_of_obfuscated_char = len(obfuscated_matches)
    has_obfuscation = 1 if no_of_obfuscated_char > 0 else 0
    obfuscation_ratio = (
        no_of_obfuscated_char / url_length
        if url_length else 0
    )

    return {
        "URLLength": url_length,
        "DomainLength": domain_length,
        "IsDomainIP": is_domain_ip,
        "NoOfSubDomain": no_of_subdomain,
        "NoOfLettersInURL": no_of_letters,
        "LetterRatioInURL": letter_ratio,
        "NoOfDegitsInURL": no_of_digits,
        "DegitRatioInURL": digit_ratio,
        "NoOfEqualsInURL": no_of_equals,
        "NoOfQMarkInURL": no_of_qmark,
        "NoOfAmpersandInURL": no_of_ampersand,
        "NoOfOtherSpecialCharsInURL": special_chars,
        "SpacialCharRatioInURL": special_char_ratio,
        "HasObfuscation": has_obfuscation,
        "NoOfObfuscatedChar": no_of_obfuscated_char,
        "ObfuscationRatio": obfuscation_ratio
    }


# Test the extractor
if __name__ == "__main__":
    test_url = "https://example.com/login?user=123"

    features = extract_features(test_url)

    print("\n===== URL FEATURES =====\n")

    for name, value in features.items():
        print(f"{name}: {value}")
