"""
Defines the different chastity modes for the ChastiPi application.
"""
from ..core.config import config
import json
from pathlib import Path

CUSTOM_MODES_PATH = Path(__file__).parent.parent.parent / "custom_modes.json"

def load_custom_modes():
    if CUSTOM_MODES_PATH.exists():
        with open(CUSTOM_MODES_PATH, "r") as f:
            return json.load(f)
    return {}

class Mode:
    """Base class for all chastity modes."""
    def __init__(self, mode_name: str):
        self.name = mode_name
        self._configure_from_settings()

    def _configure_from_settings(self):
        """
        Configures the mode based on settings for that mode from config.json.
        This allows for dynamic adjustment of mode parameters without code changes.
        """
        mode_settings = config.get(f"modes.{self.name}", {})
        self.punishments_enabled = mode_settings.get("punishments_enabled", True)
        self.cage_check_enabled = mode_settings.get("cage_check_enabled", True)
        self.timed_challenges_enabled = mode_settings.get("timed_challenges_enabled", False)
        self.random_discipline_enabled = mode_settings.get("random_discipline_enabled", False)
        self.strict_mode_features_enabled = mode_settings.get("strict_mode_features_enabled", False)

    def is_feature_enabled(self, feature_name: str) -> bool:
        """Check if a specific feature is enabled for this mode."""
        return getattr(self, f"{feature_name}_enabled", False)

class SelfHostedTestMode(Mode):
    """For testing self-hosted setups. Most features enabled, but might use mock data."""
    def __init__(self):
        super().__init__("self-hosted-test")

class GentleMode(Mode):
    """A gentler experience, likely with no punishments."""
    def __init__(self):
        super().__init__("gentle")
        self.punishments_enabled = False

class TimedChallengeMode(Mode):
    """Focuses on timed challenges, possibly with specific rewards or penalties."""
    def __init__(self):
        super().__init__("timed-challenge")
        self.timed_challenges_enabled = True

class RandomDisciplineMode(Mode):
    """Introduces random punishments or tasks."""
    def __init__(self):
        super().__init__("random-discipline")
        self.random_discipline_enabled = True

class StrictMode(Mode):
    """A more intense experience with stricter rules and consequences."""
    def __init__(self):
        super().__init__("strict")
        self.strict_mode_features_enabled = True
        # In strict mode, everything is enabled and enforced
        self.punishments_enabled = True
        self.cage_check_enabled = True

class TestMode(Mode):
    """For testing the app. Instant unlocks, no punishments."""
    def __init__(self):
        super().__init__("test")
        self.punishments_enabled = False
        self.instant_unlock_enabled = True
        self.cage_check_enabled = False
        self.timed_challenges_enabled = False
        self.random_discipline_enabled = False
        self.strict_mode_features_enabled = False

class CustomMode(Mode):
    def __init__(self, mode_name: str, settings: dict):
        self.name = mode_name
        for k, v in settings.items():
            setattr(self, k, v)

def get_current_mode() -> Mode:
    """Gets the current chastity mode from the config and returns the corresponding mode object."""
    mode_name = config.get("system.chastity_mode", "gentle")
    
    modes = {
        "self-hosted-test": SelfHostedTestMode,
        "gentle": GentleMode,
        "timed-challenge": TimedChallengeMode,
        "random-discipline": RandomDisciplineMode,
        "strict": StrictMode,
        "test": TestMode,
    }
    
    # Load custom modes
    custom_modes = load_custom_modes()
    if mode_name in custom_modes:
        return CustomMode(mode_name, custom_modes[mode_name])
    
    mode_class = modes.get(mode_name, GentleMode)
    return mode_class() 