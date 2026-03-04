#!/usr/bin/env python3
"""
Tests for fray ci and fray learn modules.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from fray.ci import (
    generate_workflow,
    generate_minimal_workflow,
    run_ci,
)
from fray.learn import (
    CHALLENGES,
    check_answer,
    load_progress,
    save_progress,
    get_topic_progress,
    list_topics,
    _progress_bar,
    _progress_file,
)
from fray import __version__


# ══════════════════════════════════════════════════════════════════════════════
# CI Module Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestGenerateWorkflow(unittest.TestCase):

    def test_default_workflow_contains_fray(self):
        yml = generate_workflow()
        self.assertIn("Fray WAF Test", yml)
        self.assertIn("pip install fray", yml)
        self.assertIn("fray detect", yml)
        self.assertIn("fray test", yml)

    def test_workflow_has_version(self):
        yml = generate_workflow()
        self.assertIn(__version__, yml)

    def test_target_url_embedded(self):
        yml = generate_workflow(target="https://example.com")
        self.assertIn("https://example.com", yml)

    def test_no_target_uses_secret(self):
        yml = generate_workflow()
        self.assertIn("FRAY_TARGET_URL", yml)

    def test_max_payloads(self):
        yml = generate_workflow(max_payloads=100)
        self.assertIn("--max 100", yml)

    def test_fail_on_bypass(self):
        yml = generate_workflow(fail_on_bypass=True)
        self.assertIn("bypass", yml.lower())

    def test_comment_on_pr_enabled(self):
        yml = generate_workflow(comment_on_pr=True)
        self.assertIn("Comment on PR", yml)

    def test_comment_on_pr_disabled(self):
        yml = generate_workflow(comment_on_pr=False)
        self.assertNotIn("Comment on PR", yml)

    def test_webhook_url(self):
        yml = generate_workflow(webhook_url="https://hooks.slack.com/test")
        self.assertIn("hooks.slack.com/test", yml)

    def test_pr_trigger(self):
        yml = generate_workflow()
        self.assertIn("pull_request", yml)

    def test_workflow_dispatch(self):
        yml = generate_workflow()
        self.assertIn("workflow_dispatch", yml)

    def test_upload_artifact(self):
        yml = generate_workflow()
        self.assertIn("upload-artifact", yml)

    def test_fray_doctor_step(self):
        yml = generate_workflow()
        self.assertIn("fray doctor", yml)


class TestGenerateMinimalWorkflow(unittest.TestCase):

    def test_minimal_is_shorter(self):
        full = generate_workflow()
        mini = generate_minimal_workflow()
        self.assertLess(len(mini), len(full))

    def test_minimal_has_core_steps(self):
        mini = generate_minimal_workflow()
        self.assertIn("pip install fray", mini)
        self.assertIn("fray detect", mini)
        self.assertIn("fray test", mini)

    def test_minimal_with_target(self):
        mini = generate_minimal_workflow(target="https://test.com")
        self.assertIn("https://test.com", mini)


class TestRunCiShow(unittest.TestCase):

    @patch("sys.stdout")
    def test_show_prints_workflow(self, mock_stdout):
        """Verify show action doesn't crash."""
        import io
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            run_ci(action="show", minimal=True)
        output = captured.getvalue()
        self.assertIn("fray", output.lower())

    def test_init_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            run_ci(action="init", output_dir=tmpdir, minimal=True)
            wf = Path(tmpdir) / ".github" / "workflows" / "fray-waf-test.yml"
            self.assertTrue(wf.exists())
            content = wf.read_text()
            self.assertIn("fray", content.lower())

    def test_init_with_target(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            run_ci(action="init", output_dir=tmpdir, target="https://target.com", minimal=True)
            wf = Path(tmpdir) / ".github" / "workflows" / "fray-waf-test.yml"
            content = wf.read_text()
            self.assertIn("https://target.com", content)


class TestCLICi(unittest.TestCase):

    def test_ci_help(self):
        from fray.cli import main
        with patch("sys.argv", ["fray", "ci", "--help"]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 0)

    def test_ci_show_minimal(self):
        from fray.cli import main
        import io
        captured = io.StringIO()
        with patch("sys.argv", ["fray", "ci", "show", "--minimal"]):
            with patch("sys.stdout", captured):
                main()
        self.assertIn("fray", captured.getvalue().lower())


# ══════════════════════════════════════════════════════════════════════════════
# Learn Module Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestChallengesDatabase(unittest.TestCase):

    def test_has_topics(self):
        self.assertGreater(len(CHALLENGES), 0)

    def test_required_topics(self):
        for topic in ("xss", "sqli", "ssrf", "cmdi"):
            self.assertIn(topic, CHALLENGES)

    def test_each_topic_has_levels(self):
        for key, topic in CHALLENGES.items():
            self.assertIn("title", topic)
            self.assertIn("levels", topic)
            self.assertGreater(len(topic["levels"]), 0, f"{key} has no levels")

    def test_each_level_has_required_fields(self):
        required = {"level", "title", "difficulty", "scenario", "hint",
                    "valid_answers", "accept_pattern", "explanation", "points"}
        for key, topic in CHALLENGES.items():
            for lv in topic["levels"]:
                for field in required:
                    self.assertIn(field, lv, f"{key} level {lv.get('level')} missing '{field}'")

    def test_levels_are_sequential(self):
        for key, topic in CHALLENGES.items():
            levels = [lv["level"] for lv in topic["levels"]]
            self.assertEqual(levels, list(range(1, len(levels) + 1)),
                             f"{key} levels not sequential: {levels}")

    def test_points_are_positive(self):
        for key, topic in CHALLENGES.items():
            for lv in topic["levels"]:
                self.assertGreater(lv["points"], 0, f"{key} L{lv['level']} has 0 points")

    def test_total_challenges_count(self):
        total = sum(len(t["levels"]) for t in CHALLENGES.values())
        self.assertEqual(total, 16)


class TestCheckAnswer(unittest.TestCase):

    def test_xss_level1_exact(self):
        challenge = CHALLENGES["xss"]["levels"][0]
        self.assertTrue(check_answer("<script>alert(1)</script>", challenge))

    def test_xss_level1_variant(self):
        challenge = CHALLENGES["xss"]["levels"][0]
        self.assertTrue(check_answer("<script>alert('xss')</script>", challenge))

    def test_xss_level1_wrong(self):
        challenge = CHALLENGES["xss"]["levels"][0]
        self.assertFalse(check_answer("hello world", challenge))

    def test_xss_level2_event_handler(self):
        challenge = CHALLENGES["xss"]["levels"][1]
        self.assertTrue(check_answer("<img src=x onerror=alert(1)>", challenge))

    def test_xss_level2_svg(self):
        challenge = CHALLENGES["xss"]["levels"][1]
        self.assertTrue(check_answer("<svg onload=alert(1)>", challenge))

    def test_sqli_level1_or(self):
        challenge = CHALLENGES["sqli"]["levels"][0]
        self.assertTrue(check_answer("' OR 1=1--", challenge))

    def test_sqli_level1_admin(self):
        challenge = CHALLENGES["sqli"]["levels"][0]
        self.assertTrue(check_answer("admin'--", challenge))

    def test_sqli_level2_union(self):
        challenge = CHALLENGES["sqli"]["levels"][1]
        self.assertTrue(check_answer("1 UNION SELECT version(),null--", challenge))

    def test_ssrf_level1_metadata(self):
        challenge = CHALLENGES["ssrf"]["levels"][0]
        self.assertTrue(check_answer("http://169.254.169.254/latest/meta-data/", challenge))

    def test_ssrf_level2_decimal_ip(self):
        challenge = CHALLENGES["ssrf"]["levels"][1]
        self.assertTrue(check_answer("http://2852039166/latest/meta-data/", challenge))

    def test_cmdi_level1_semicolon(self):
        challenge = CHALLENGES["cmdi"]["levels"][0]
        self.assertTrue(check_answer("127.0.0.1; cat /etc/passwd", challenge))

    def test_cmdi_level1_pipe(self):
        challenge = CHALLENGES["cmdi"]["levels"][0]
        self.assertTrue(check_answer("| cat /etc/passwd", challenge))

    def test_wrong_answer_returns_false(self):
        for key, topic in CHALLENGES.items():
            for lv in topic["levels"]:
                self.assertFalse(check_answer("this is not a valid payload xyz123", lv),
                                 f"False positive on {key} L{lv['level']}")


class TestProgressTracking(unittest.TestCase):

    def setUp(self):
        self._orig_home = os.environ.get("HOME")
        self._tmpdir = tempfile.mkdtemp()
        os.environ["HOME"] = self._tmpdir

    def tearDown(self):
        if self._orig_home:
            os.environ["HOME"] = self._orig_home
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_load_empty_progress(self):
        progress = load_progress()
        self.assertEqual(progress["total_points"], 0)
        self.assertEqual(progress["challenges_solved"], 0)
        self.assertIsInstance(progress["topics"], dict)

    def test_save_and_load(self):
        progress = load_progress()
        progress["total_points"] = 42
        progress["topics"]["xss"] = {"completed_levels": [1, 2], "points": 25}
        save_progress(progress)

        loaded = load_progress()
        self.assertEqual(loaded["total_points"], 42)
        self.assertEqual(loaded["topics"]["xss"]["points"], 25)
        self.assertEqual(loaded["topics"]["xss"]["completed_levels"], [1, 2])

    def test_get_topic_progress_new(self):
        progress = load_progress()
        tp = get_topic_progress(progress, "xss")
        self.assertEqual(tp["completed_levels"], [])
        self.assertEqual(tp["points"], 0)

    def test_get_topic_progress_existing(self):
        progress = {"topics": {"sqli": {"completed_levels": [1], "points": 10}},
                     "total_points": 10, "challenges_solved": 1}
        tp = get_topic_progress(progress, "sqli")
        self.assertEqual(tp["completed_levels"], [1])


class TestProgressBar(unittest.TestCase):

    def test_empty_bar(self):
        bar = _progress_bar(0, 5)
        self.assertIn("[", bar)
        self.assertIn("]", bar)

    def test_full_bar(self):
        bar = _progress_bar(5, 5)
        self.assertIn("[", bar)

    def test_partial_bar(self):
        bar = _progress_bar(2, 5)
        self.assertIn("[", bar)

    def test_zero_total(self):
        bar = _progress_bar(0, 0)
        self.assertIn("[", bar)


class TestListTopics(unittest.TestCase):

    def test_list_topics_no_crash(self):
        """Verify list_topics runs without error."""
        import io
        progress = load_progress()
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            list_topics(progress)
        output = captured.getvalue()
        self.assertIn("XSS", output)
        self.assertIn("SQL", output)
        self.assertIn("SSRF", output)
        self.assertIn("Command", output)


class TestCLILearn(unittest.TestCase):

    def test_learn_help(self):
        from fray.cli import main
        with patch("sys.argv", ["fray", "learn", "--help"]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 0)

    def test_learn_list(self):
        from fray.cli import main
        import io
        captured = io.StringIO()
        with patch("sys.argv", ["fray", "learn", "--list"]):
            with patch("sys.stdout", captured):
                main()
        self.assertIn("XSS", captured.getvalue())

    def test_learn_reset(self):
        from fray.cli import main
        import io
        captured = io.StringIO()
        with patch("sys.argv", ["fray", "learn", "--reset"]):
            with patch("sys.stdout", captured):
                main()


class TestLearnReset(unittest.TestCase):

    def setUp(self):
        self._orig_home = os.environ.get("HOME")
        self._tmpdir = tempfile.mkdtemp()
        os.environ["HOME"] = self._tmpdir

    def tearDown(self):
        if self._orig_home:
            os.environ["HOME"] = self._orig_home
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_reset_clears_progress(self):
        from fray.learn import run_learn
        # Save some progress
        progress = {"topics": {"xss": {"completed_levels": [1], "points": 10}},
                     "total_points": 10, "challenges_solved": 1}
        save_progress(progress)
        self.assertTrue(_progress_file().exists())

        # Reset
        run_learn(reset=True)
        self.assertFalse(_progress_file().exists())


if __name__ == "__main__":
    unittest.main()
