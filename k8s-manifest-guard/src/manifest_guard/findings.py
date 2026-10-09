"""Finding model shared by checks and reporters."""
from dataclasses import dataclass

SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"


@dataclass
class Finding:
    check_id: str
    severity: str
    workload: str
    container: str
    message: str

    def to_dict(self):
        return {
            "check": self.check_id,
            "severity": self.severity,
            "workload": self.workload,
            "container": self.container,
            "message": self.message,
        }
