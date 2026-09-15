from crypto.benchmarks.legacy_ciphers import benchmark_des, benchmark_3des, benchmark_blowfish, LEGACY_DISCLAIMER


def test_des_benchmark_correctness_asserted_internally():
    # benchmark_des() has an internal assert that the round-trip matches;
    # if it didn't, this call would raise AssertionError.
    result = benchmark_des(b"test payload data")
    assert result.algorithm == "DES"
    assert result.disclaimer == LEGACY_DISCLAIMER


def test_3des_benchmark_correctness_asserted_internally():
    result = benchmark_3des(b"test payload data")
    assert result.algorithm == "3DES"


def test_blowfish_benchmark_correctness_asserted_internally():
    result = benchmark_blowfish(b"test payload data")
    assert result.algorithm == "Blowfish"


def test_all_legacy_algorithms_have_disclaimer():
    for fn in (benchmark_des, benchmark_3des, benchmark_blowfish):
        result = fn(b"data")
        assert "historical/performance comparison only" in result.disclaimer
        assert "NOT used anywhere in this system" in result.disclaimer


def test_legacy_timings_non_negative():
    for fn in (benchmark_des, benchmark_3des, benchmark_blowfish):
        result = fn(b"payload" * 100)
        assert result.key_generation_seconds >= 0
        assert result.payload_encryption_seconds >= 0
        assert result.payload_decryption_seconds >= 0


def test_legacy_ciphertext_larger_due_to_padding():
    # Block ciphers with padding will generally produce ciphertext >= payload
    for fn in (benchmark_des, benchmark_3des, benchmark_blowfish):
        result = fn(b"short")
        assert result.ciphertext_size_bytes >= len(b"short")
