import unittest
from risk_engine import assess_platform, verify_report, LocalLedger, analyze

BAD = "function mint(address a) onlyOwner {} function withdrawAll() {} blacklist"


class T(unittest.TestCase):
    def test_flags_fraud(self):
        self.assertEqual(analyze(BAD, "guaranteed returns")["verdict"], "likely_fraudulent")

    def test_proof_and_tamper(self):
        led = LocalLedger()
        r = assess_platform(BAD, anchor=led)
        self.assertTrue(verify_report(r["report"], r["proof"], led))
        r["report"]["risk_score"] = 0
        self.assertFalse(verify_report(r["report"], r["proof"], led))


if __name__ == "__main__":
    unittest.main()
