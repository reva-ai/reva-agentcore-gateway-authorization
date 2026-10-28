import contextlib
import io
import os
import unittest
from unittest import mock

from interceptor import secret
from interceptor.config import Settings
from interceptor.secret import CACHE_SECONDS, SecretError, get_token, with_token


class FakeSecrets:
    """Just enough of a Secrets Manager client: answers from a script, records the requests."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def get_secret_value(self, **kwargs):
        self.calls.append(kwargs)
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def text(value):
    return {"SecretString": value}


class ReadingTheSecret(unittest.TestCase):
    def setUp(self):
        secret._CACHE.clear()
        self.addCleanup(secret._CACHE.clear)
        self.now = [1000.0]
        self.client = FakeSecrets()
        for name, replacement in (("_client", lambda secret_id: self.client),
                                  ("_clock", lambda: self.now[0])):
            patcher = mock.patch.object(secret, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.cfg = Settings.from_env({})

    def test_a_plaintext_secret_is_the_token(self):
        self.client.responses = [text(" tok-1\n")]
        self.assertEqual(get_token(self.cfg), "tok-1")
        self.assertEqual(self.client.calls, [{"SecretId": "reva/secrets"}])

    def test_a_json_secret_is_read_at_the_key(self):
        self.client.responses = [text('{"RTG_TOKEN": "tok-2", "other": "x"}')]
        self.assertEqual(get_token(self.cfg), "tok-2")
        secret._CACHE.clear()
        self.client.responses = [text('{"rtg": "tok-3"}')]
        self.assertEqual(get_token(Settings.from_env({"REVA_TOKEN_SECRET_KEY": "rtg"})), "tok-3")

    def test_the_key_can_be_overridden_and_only_that_field_is_used(self):
        # the default key names a different field in the same secret: it must be ignored
        self.client.responses = [text('{"RTG_TOKEN": "not-this", "ACME_RTG_TOKEN": "acme-token"}')]
        cfg = Settings.from_env({"REVA_TOKEN_SECRET_KEY": "ACME_RTG_TOKEN"})
        self.assertEqual(get_token(cfg), "acme-token")
        self.assertEqual(self.client.calls, [{"SecretId": "reva/secrets"}])    # still fetched by name

    def test_the_secret_can_be_named_by_arn(self):
        arn = "arn:aws:secretsmanager:us-west-2:111122223333:secret:mine-AbCdEf"
        self.client.responses = [text("tok")]
        get_token(Settings.from_env({"REVA_TOKEN_SECRET": arn}))
        self.assertEqual(self.client.calls, [{"SecretId": arn}])

    def test_a_json_secret_without_the_key_is_an_error_that_leaves_the_value_out(self):
        self.client.responses = [text('{"other": "do-not-leak-me"}')]
        with self.assertRaises(SecretError) as caught:
            get_token(self.cfg)
        self.assertIn("'RTG_TOKEN'", str(caught.exception))
        self.assertNotIn("do-not-leak-me", str(caught.exception))

    def test_an_empty_or_binary_secret_is_an_error(self):
        for response in (text("  "), {"SecretBinary": b"bytes"}):
            self.client.responses = [response]
            with self.assertRaises(SecretError):
                get_token(self.cfg)

    def test_a_failed_read_names_the_secret_not_its_value(self):
        self.client.responses = [RuntimeError("AccessDeniedException: not authorized")]
        with self.assertRaises(SecretError) as caught:
            get_token(self.cfg)
        self.assertIn("reva/secrets", str(caught.exception))
        self.assertIn("AccessDeniedException", str(caught.exception))

    def test_the_token_is_cached_and_a_rotation_is_picked_up_after_the_cache_time(self):
        self.client.responses = [text("old"), text("rotated")]
        self.assertEqual(get_token(self.cfg), "old")
        self.now[0] += CACHE_SECONDS - 1
        self.assertEqual(get_token(self.cfg), "old")
        self.assertEqual(len(self.client.calls), 1)
        self.now[0] += 1
        self.assertEqual(get_token(self.cfg), "rotated")
        self.assertEqual(len(self.client.calls), 2)

    def test_a_failed_refresh_keeps_the_last_token_and_waits_before_trying_again(self):
        self.client.responses = [text("good"), RuntimeError("throttled")]
        get_token(self.cfg)
        self.now[0] += CACHE_SECONDS
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.assertEqual(get_token(self.cfg), "good")
            self.assertEqual(get_token(self.cfg), "good")
        self.assertEqual(len(self.client.calls), 2)
        self.assertEqual(buffer.getvalue().count("token_refresh_failed"), 1)
        self.assertNotIn("good", buffer.getvalue())

    def test_a_first_failure_is_not_remembered(self):
        self.client.responses = [RuntimeError("down"), text("tok")]
        with self.assertRaises(SecretError):
            get_token(self.cfg)
        self.assertEqual(get_token(self.cfg), "tok")


class WithToken(unittest.TestCase):
    def setUp(self):
        secret._CACHE.clear()
        self.addCleanup(secret._CACHE.clear)

    def test_the_token_is_put_on_a_copy_of_the_settings(self):
        cfg = Settings.from_env({})
        with mock.patch.object(secret, "get_token", return_value="tok") as get:
            ready = with_token(cfg)
        self.assertEqual((ready.token, cfg.token), ("tok", ""))
        get.assert_called_once_with(cfg)

    def test_a_token_already_on_the_settings_is_not_looked_up(self):
        import dataclasses
        cfg = dataclasses.replace(Settings.from_env({}), token="given")
        with mock.patch.object(secret, "get_token") as get:
            self.assertIs(with_token(cfg), cfg)
        get.assert_not_called()


class WhichRegion(unittest.TestCase):
    """A secret named by ARN is asked for in the ARN's region, which is how another account's is reached."""

    def options(self, secret_id):
        with mock.patch("boto3.client") as make:
            secret._client(secret_id)
        return make.call_args.kwargs

    def test_an_arn_selects_its_own_region(self):
        arn = "arn:aws:secretsmanager:eu-west-1:111122223333:secret:reva/secrets-AbCdEf"
        self.assertEqual(self.options(arn)["region_name"], "eu-west-1")
        gov = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:reva/secrets-AbCdEf"
        self.assertEqual(self.options(gov)["region_name"], "us-gov-west-1")

    def test_a_name_uses_the_functions_own_region(self):
        self.assertNotIn("region_name", self.options("reva/secrets"))
        self.assertNotIn("region_name", self.options("arn:aws:s3:::not-a-secret"))


class SecretsManagerRequestIsValid(unittest.TestCase):
    """botocore's Stubber checks the request against the Secrets Manager API model."""

    def test_get_secret_value_request_and_response(self):
        try:
            import boto3
            from botocore.stub import Stubber
        except ImportError:                                  # pragma: no cover
            self.skipTest("boto3 is not installed")
        env = {"AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "x",
               "AWS_DEFAULT_REGION": "us-west-2"}
        with mock.patch.dict(os.environ, env):
            client = boto3.client("secretsmanager")
        secret._CACHE.clear()
        self.addCleanup(secret._CACHE.clear)
        with Stubber(client) as stubber, mock.patch.object(secret, "_client", lambda secret_id: client):
            stubber.add_response("get_secret_value", {"SecretString": "stubbed-token"},
                                 {"SecretId": "reva/secrets"})
            self.assertEqual(get_token(Settings.from_env({})), "stubbed-token")
            stubber.assert_no_pending_responses()


if __name__ == "__main__":
    unittest.main()
