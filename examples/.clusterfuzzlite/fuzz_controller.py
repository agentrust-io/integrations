#!/usr/bin/python3
"""Fuzz the industrial example's mock safety controller.

request_motion() receives the motion request an agent sends through the cMCP
gateway, arriving as JSON over HTTP. It must either accept a motion inside the
controller's envelope or raise SafetyRejected. The target mints a genuine state
token most of the time, so inputs get past the HMAC and reach the envelope
checks, then fuzzes the rest of the request.

Two bugs sat here before the target: a NaN speed compared false against both
bounds and was accepted, and an integer too large for a float raised
OverflowError instead of SafetyRejected.
"""
import math
import sys
from pathlib import Path

import atheris

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "industrial-embodied-ai"))

with atheris.instrument_imports():
    from controller import (
        ALLOWED_TARGETS,
        MAX_SPEED_MPS,
        IndependentSafetyController,
        SafetyRejected,
    )

_TARGETS = sorted(ALLOWED_TARGETS)


class _Clock:
    value = 1_781_179_200.0

    def __call__(self) -> float:
        return self.value


def _speed(fdp: atheris.FuzzedDataProvider) -> object:
    kind = fdp.ConsumeIntInRange(0, 6)
    if kind == 0:
        return fdp.ConsumeRegularFloat()
    if kind == 1:
        return fdp.ConsumeFloat()  # includes NaN and the infinities
    if kind == 2:
        return fdp.ConsumeInt(fdp.ConsumeIntInRange(1, 256))
    if kind == 3:
        return fdp.ConsumeUnicodeNoSurrogates(24)
    if kind == 4:
        return fdp.ConsumeBool()
    if kind == 5:
        return None
    return [fdp.ConsumeRegularFloat()]


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    clock = _Clock()
    controller = IndependentSafetyController(clock=clock, token_key=b"fuzz-only-controller-key")
    token = controller.read_safety_state()["state_token"]
    if fdp.ConsumeIntInRange(0, 7) == 0:
        token = fdp.ConsumeUnicodeNoSurrogates(256)
    clock.value += fdp.ConsumeIntInRange(0, 6000) / 1000
    request: dict[str, object] = {"safety_state_token": token}
    if fdp.ConsumeBool():
        request["motion_id"] = fdp.ConsumeUnicodeNoSurrogates(16)
    if fdp.ConsumeBool():
        request["target"] = (
            _TARGETS[fdp.ConsumeIntInRange(0, len(_TARGETS) - 1)]
            if fdp.ConsumeBool()
            else fdp.ConsumeUnicodeNoSurrogates(24)
        )
    if fdp.ConsumeIntInRange(0, 9):
        request["max_speed_mps"] = _speed(fdp)

    try:
        result = controller.request_motion(request)
    except SafetyRejected:
        return
    speed = float(request["max_speed_mps"])
    assert math.isfinite(speed) and 0 <= speed <= MAX_SPEED_MPS, request
    assert request["target"] in ALLOWED_TARGETS, request
    assert result["controller_decision"] == "accepted", result


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
