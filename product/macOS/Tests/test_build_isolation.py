"""No build, application launch, credential access or network during these tests."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / "build.py"
SPEC = importlib.util.spec_from_file_location("mfa_product_build", SCRIPT)
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


class BuildIsolationTests(unittest.TestCase):
    def test_runtime_contains_product_codec_without_research_executor_or_tests(self):
        sources = [source.relative_to(BUILD.ROOT / "service") for source in BUILD.runtime_sources()]
        self.assertIn(Path("main.py"), sources)
        self.assertIn(Path("bootstrap.py"), sources)
        self.assertIn(Path("remotengc.py"), sources)
        self.assertNotIn(Path("ngc_bootstrap.py"), sources)
        self.assertTrue(all(source.suffix == ".py" for source in sources))
        self.assertTrue(all(not {"tests", "__pycache__"}.intersection(source.parts) for source in sources))

    def test_separate_output_keeps_default_bundle_distinct(self):
        old_derived, old_app, _ = BUILD.build_paths(None)
        new_derived, new_app, log = BUILD.build_paths("product/build/RemoteNGC/DerivedData")
        self.assertNotEqual(old_derived, new_derived)
        self.assertNotEqual(old_app, new_app)
        self.assertEqual(log.parent, new_derived.parent)
        BUILD.ensure_target_not_running(new_app, [str(old_app)])

    def test_running_target_is_rejected(self):
        _, app, _ = BUILD.build_paths(None)
        with self.assertRaisesRegex(RuntimeError, "target app is running"):
            BUILD.ensure_target_not_running(app, [str(app)])

    def test_symlink_to_running_target_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "synthetic.app"
            app.mkdir()
            alias = root / "alias.app"
            alias.symlink_to(app, target_is_directory=True)
            with self.assertRaises(RuntimeError):
                BUILD.ensure_target_not_running(alias, [str(app)])


if __name__ == "__main__":
    unittest.main()
