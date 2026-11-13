from password_auditor.entropy import calculate_entropy, pool_size


def test_empty_password_is_zero():
    assert calculate_entropy("") == 0.0


def test_pool_sizes_by_class():
    assert pool_size("abc") == 26
    assert pool_size("abcABC") == 52
    assert pool_size("abc123") == 36
    assert pool_size("abc!") == 26 + 32  # punctuation pool is 32


def test_underscore_is_not_zero():
    # Regression: the old [\W] rule scored an underscore-only password as 0.
    assert pool_size("____") > 0
    assert calculate_entropy("____") > 0


def test_longer_password_scores_higher():
    assert calculate_entropy("aaaaaaaa") < calculate_entropy("aaaaaaaaaaaaaaaa")


def test_non_ascii_gets_a_pool():
    assert pool_size("café") >= 100
