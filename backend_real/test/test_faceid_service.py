from pathlib import Path

import pytest

from backend_real.services.faceid_service import FaceIdService


class _FakeRecognizer:
    def __init__(self, label: int = 1, confidence: float = 50.0) -> None:
        self.label = label
        self.confidence = confidence
        self.read_called = False

    def read(self, _path: str) -> None:
        self.read_called = True

    def predict(self, _processed_face):
        return self.label, self.confidence


def _build_service(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str) -> FaceIdService:
    models_dir = tmp_path / "models"
    samples_dir = tmp_path / "samples"
    monkeypatch.setenv("FACEID_MODELS_DIR", str(models_dir))
    monkeypatch.setenv("FACEID_SAMPLES_DIR", str(samples_dir))
    monkeypatch.setenv("FACEID_LIVENESS_MODE", mode)

    service = FaceIdService()
    model_path = service._model_path_for("Usuario@Test.com")
    model_path.parent.mkdir(parents=True, exist_ok=True)
    model_path.write_text("modelo-falso", encoding="utf-8")

    monkeypatch.setattr(service, "_ensure_runtime_available", lambda: None)
    monkeypatch.setattr(service, "_decode_image", lambda _image: "frame")
    monkeypatch.setattr(service, "_extract_primary_face", lambda _frame: "face-gray")
    monkeypatch.setattr(service, "_preprocess_face", lambda face: face)
    return service


def test_normalize_user_key_lowercase_trim_and_replace() -> None:
    normalized = FaceIdService._normalize_user_key("  UsEr Invalido###@Mail.Com  ")
    assert normalized == "user_invalido_@mail.com"


@pytest.mark.parametrize("bad_value", ["", "   ", None])
def test_normalize_user_key_invalid_value_raises_error(bad_value) -> None:
    with pytest.raises(ValueError):
        FaceIdService._normalize_user_key(bad_value)


def test_verify_user_enforce_blocks_when_liveness_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    service = _build_service(monkeypatch, tmp_path, mode="enforce")
    monkeypatch.setattr(service, "_check_liveness_blur", lambda _face: False)

    recognizer = _FakeRecognizer()
    monkeypatch.setattr(service, "_create_lbph", lambda: recognizer)

    result = service.verify_user("Usuario@Test.com", "imagen-base64")

    assert result.autorizado is False
    assert result.confianza_lbph is None
    assert result.rostros_detectados == 1
    assert recognizer.read_called is False


def test_verify_user_warn_allows_recognition_when_liveness_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    service = _build_service(monkeypatch, tmp_path, mode="warn")
    monkeypatch.setattr(service, "_check_liveness_blur", lambda _face: False)

    recognizer = _FakeRecognizer(label=1, confidence=20.0)
    monkeypatch.setattr(service, "_create_lbph", lambda: recognizer)

    result = service.verify_user("Usuario@Test.com", "imagen-base64")

    assert result.autorizado is True
    assert result.confianza_lbph == 20.0
    assert result.rostros_detectados == 1
    assert recognizer.read_called is True


def test_verify_user_off_skips_liveness_check(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    service = _build_service(monkeypatch, tmp_path, mode="off")

    def _should_not_run(_face):
        raise AssertionError("_check_liveness_blur no debe ejecutarse en modo off")

    monkeypatch.setattr(service, "_check_liveness_blur", _should_not_run)

    recognizer = _FakeRecognizer(label=1, confidence=15.0)
    monkeypatch.setattr(service, "_create_lbph", lambda: recognizer)

    result = service.verify_user("Usuario@Test.com", "imagen-base64")

    assert result.autorizado is True
    assert result.confianza_lbph == 15.0
    assert result.rostros_detectados == 1
    assert recognizer.read_called is True