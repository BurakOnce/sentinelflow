from pathlib import Path


class RuleError(ValueError):
    def __init__(self, rule: str, message: str, path: Path | None = None) -> None:
        location = f"{path}: " if path else ""
        super().__init__(f"{location}rule {rule!r}: {message}")
        self.rule = rule
        self.message = message
        self.path = path

    def at(self, path: Path) -> "RuleError":
        return RuleError(self.rule, self.message, path)
