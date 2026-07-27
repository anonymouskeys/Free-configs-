#!/usr/bin/env python3
import unittest
from pathlib import Path


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (
            Path(__file__).resolve().parents[1]
            / ".github"
            / "workflows"
            / "update-configs.yml"
        ).read_text(encoding="utf-8")

    def test_runs_every_four_hours(self) -> None:
        self.assertIn('cron: "17 */4 * * *"', self.workflow)

    def test_generates_and_commits_dynamic_readme(self) -> None:
        self.assertIn("python scripts/generate_readme.py", self.workflow)
        self.assertIn("git add -- output/ README.md", self.workflow)
        self.assertIn("test -s README.md", self.workflow)

    def test_push_retries_after_remote_update(self) -> None:
        self.assertIn('git pull --rebase origin "${GITHUB_REF_NAME}"', self.workflow)
        self.assertIn('git push origin "HEAD:${GITHUB_REF_NAME}"', self.workflow)


if __name__ == "__main__":
    unittest.main()
