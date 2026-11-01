from feature_extractor import extract_features

EXPECTED = [
    "URLLength", "DomainLength", "IsDomainIP", "NoOfSubDomain",
    "NoOfLettersInURL", "LetterRatioInURL", "NoOfDegitsInURL",
    "DegitRatioInURL", "NoOfEqualsInURL", "NoOfQMarkInURL",
    "NoOfAmpersandInURL", "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL", "HasObfuscation", "NoOfObfuscatedChar",
    "ObfuscationRatio",
]

def test_feature_schema_and_values():
    result = extract_features("https://example.com/login?user=123")
    assert list(result) == EXPECTED
    assert result["URLLength"] > 0
    assert result["HasObfuscation"] == 0

def test_encoded_url_detected():
    result = extract_features("https://example.com/%2Flogin")
    assert result["HasObfuscation"] == 1
