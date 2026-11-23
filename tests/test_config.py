import unittest

from interceptor.config import Settings


def build(**env):
    return Settings.from_env(env)


class TokenSecret(unittest.TestCase):
    def test_the_secret_defaults_to_reva_secrets_and_nothing_is_required(self):
        bare = Settings.from_env({})
        self.assertEqual((bare.token_secret, bare.token_secret_key), ("reva/secrets", "RTG_TOKEN"))
        self.assertEqual((bare.token, bare.errors), ("", ()))

    def test_the_secret_can_be_named(self):
        cfg = build(REVA_TOKEN_SECRET="arn:aws:secretsmanager:us-west-2:1:secret:mine-AbCdEf",
                    REVA_TOKEN_SECRET_KEY="rtg")
        self.assertEqual(cfg.token_secret, "arn:aws:secretsmanager:us-west-2:1:secret:mine-AbCdEf")
        self.assertEqual(cfg.token_secret_key, "rtg")
        self.assertEqual(build(REVA_TOKEN_SECRET="", REVA_TOKEN_SECRET_KEY="").token_secret,
                         "reva/secrets")

    def test_a_token_in_the_environment_is_reported_and_never_used(self):
        cfg = build(REVA_TOKEN="plain-token")
        self.assertEqual(cfg.token, "")
        self.assertEqual(len(cfg.errors), 1)
        self.assertIn("Secrets Manager", cfg.errors[0])
        self.assertNotIn("plain-token", cfg.errors[0])


class TolerantParsing(unittest.TestCase):
    def test_a_bad_value_is_recorded_and_the_default_kept(self):
        cfg = build(REVA_TIMEOUT_SECONDS="soon", REVA_RETRIES="-1", REVA_TARGETS="{not json")
        self.assertEqual((cfg.timeout_seconds, cfg.retries, cfg.targets), (15.0, 1, {}))
        self.assertEqual(len(cfg.errors), 3)

    def test_the_host_is_api_reva_ai_unless_named(self):
        bare = Settings.from_env({})
        self.assertEqual(bare.evaluate_url, "https://api.reva.ai/pdp/ai/access/ai/evaluation")
        self.assertEqual(build(REVA_BASE_URL="  ").base_url, "https://api.reva.ai")

    def test_base_url_forms(self):
        self.assertEqual(build(REVA_BASE_URL="api.reva.ai").evaluate_url,
                         "https://api.reva.ai/pdp/ai/access/ai/evaluation")
        self.assertEqual(build(REVA_BASE_URL="https://x.example/").base_url, "https://x.example")
        self.assertEqual(build(REVA_BASE_URL="localhost:8080").base_url, "http://localhost:8080")

    def test_targets_are_validated(self):
        self.assertTrue(build(REVA_TARGETS='{"a": {"kind": "agent"}}').errors)
        self.assertTrue(build(REVA_TARGETS='{"a": {"colour": "red"}}').errors)
        self.assertEqual(build(REVA_TARGETS='{"a": {"id": "b", "kind": "skip"}}').errors, ())


class BodyContext(unittest.TestCase):
    def test_pairs_from_the_request_body_are_sent_unless_turned_off(self):
        self.assertTrue(build().context_from_body)
        self.assertFalse(build(REVA_CONTEXT_FROM_BODY="false").context_from_body)


if __name__ == "__main__":
    unittest.main()
