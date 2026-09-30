# (resource, operation, allowed_with_temporary_token)
ROLE_PERMISSIONS = {
    "temperature-sensor": [("telemetry/temperature", "WRITE", True), ("config/self", "READ", True)],
    "pressure-sensor":    [("telemetry/pressure", "WRITE", True), ("config/self", "READ", True)],
    "smart-meter":        [("telemetry/energy", "WRITE", True), ("config/self", "READ", True)],
    "camera":             [("stream/video", "WRITE", True), ("config/self", "READ", True)],
    "valve-controller":   [("actuator/valve", "OPEN", False), ("actuator/valve", "CLOSE", False),
                           ("telemetry/valve", "WRITE", True), ("telemetry/pressure", "READ", True)],
    "motor-controller":   [("production-line", "START", False), ("production-line", "STOP", False),
                           ("telemetry/motor", "WRITE", True)],
    "plc":                [("production-line", "START", False), ("production-line", "STOP", False),
                           ("actuator/valve", "OPEN", False), ("actuator/valve", "CLOSE", False),
                           ("telemetry/line", "READ", True)],
}


class AccessPolicy:
    """Authorization: may a device with this ROLE do this OPERATION on this RESOURCE?"""

    def __init__(self, permissions=ROLE_PERMISSIONS):
        self.permissions = permissions

    def evaluate(self, device_type, resource, operation, provisional):
        """Returns (allowed, reason). provisional=True means the device is using a temporary token."""
        rules = self.permissions.get(device_type)
        if rules is None:
            return False, f"POLICY_DENY: unknown role '{device_type}'"
        for rule_resource, rule_op, provisional_ok in rules:
            if rule_resource == resource and rule_op == operation:
                if provisional and not provisional_ok:
                    return False, (f"POLICY_DENY: '{operation} {resource}' needs a permanent "
                                   f"(batch-verified) identity, a temporary token is not enough")
                return True, f"POLICY_ALLOW: '{device_type}' may {operation} {resource}"
        return False, f"POLICY_DENY: '{device_type}' may not {operation} {resource}"

    def provisional_scope(self, device_type):
        """The safe permissions written into a temporary token, e.g. ['WRITE:telemetry/valve', ...]."""
        return [f"{op}:{res}" for res, op, ok in self.permissions.get(device_type, []) if ok]