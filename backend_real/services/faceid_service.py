from __future__ import annotations

import base64
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    import cv2  # type: ignore
except Exception:  # pragma: no cover - entorno sin opencv
    cv2 = None  # type: ignore

try:
    import numpy as np  # type: ignore
except Exception:  # pragma: no cover - entorno sin numpy
    np = None  # type: ignore


@dataclass
class FaceVerificationResult:
    autorizado: bool
    confianza_lbph: Optional[float]
    rostros_detectados: int


class FaceIdService:
    def __init__(self) -> None:
        base_path = Path(__file__).resolve().parents[1]
        self._samples_path = Path(
            os.getenv("FACEID_SAMPLES_DIR", str(base_path / "faceid_data"))
        )
        self._models_path = Path(
            os.getenv("FACEID_MODELS_DIR", str(base_path / "faceid_models"))
        )
        self._face_size = (160, 160)
        self._confidence_threshold = float(os.getenv("FACEID_CONFIDENCE_THRESHOLD", "65"))
        self._min_samples = int(os.getenv("FACEID_MIN_SAMPLES", "8"))

        self._samples_path.mkdir(parents=True, exist_ok=True)
        self._models_path.mkdir(parents=True, exist_ok=True)

        self._haar_detector = None
        if cv2 is not None:
            self._haar_detector = cv2.CascadeClassifier(
                cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
            )

    @staticmethod
    def _normalize_user_key(user_key: str) -> str:
        normalized = str(user_key or "").strip().lower()
        if not normalized:
            raise ValueError("Usuario invalido para perfil facial")
        return re.sub(r"[^a-z0-9_.@-]+", "_", normalized)

    def _model_path_for(self, user_key: str) -> Path:
        safe_user = self._normalize_user_key(user_key)
        return self._models_path / f"{safe_user}.yml"

    def _samples_dir_for(self, user_key: str) -> Path:
        safe_user = self._normalize_user_key(user_key)
        return self._samples_path / safe_user

    def _ensure_runtime_available(self) -> None:
        if cv2 is None or np is None:
            raise RuntimeError(
                "FaceID requiere OpenCV y NumPy instalados en el backend (opencv-contrib-python + numpy)."
            )
        if self._haar_detector is None or self._haar_detector.empty():
            raise RuntimeError("No se pudo inicializar el detector facial Haar de OpenCV.")

    @staticmethod
    def _strip_data_url_prefix(image_b64: str) -> str:
        raw = str(image_b64 or "").strip()
        if not raw:
            raise ValueError("Imagen de FaceID vacia")
        if raw.startswith("data:"):
            parts = raw.split(",", 1)
            if len(parts) != 2:
                raise ValueError("Data URL de imagen invalida")
            return parts[1]
        return raw

    def _decode_image(self, image_b64: str):
        self._ensure_runtime_available()
        try:
            binary = base64.b64decode(self._strip_data_url_prefix(image_b64), validate=True)
        except Exception as exc:
            raise ValueError("Imagen FaceID no es base64 valida") from exc

        frame_np = np.frombuffer(binary, dtype=np.uint8)
        frame_bgr = cv2.imdecode(frame_np, cv2.IMREAD_COLOR)
        if frame_bgr is None:
            raise ValueError("No se pudo decodificar la imagen FaceID")
        return frame_bgr

    def _extract_primary_face(self, frame_bgr):
        self._ensure_runtime_available()
        gray = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2GRAY)
        detections = self._haar_detector.detectMultiScale(
            gray,
            scaleFactor=1.2,
            minNeighbors=5,
            minSize=(64, 64),
        )
        if len(detections) == 0:
            return None

        x, y, w, h = max(detections, key=lambda box: int(box[2]) * int(box[3]))
        face_gray = gray[y : y + h, x : x + w]
        if face_gray.size == 0:
            return None
        return face_gray

    def _preprocess_face(self, face_gray):
        resized = cv2.resize(face_gray, self._face_size)
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        return clahe.apply(resized)

    def _create_lbph(self):
        self._ensure_runtime_available()
        face_module = getattr(cv2, "face", None)
        if face_module is None or not hasattr(face_module, "LBPHFaceRecognizer_create"):
            raise RuntimeError(
                "OpenCV instalado sin modulo face. Instala opencv-contrib-python para habilitar FaceID."
            )
        return face_module.LBPHFaceRecognizer_create()

    def has_enrollment(self, user_key: str) -> bool:
        return self._model_path_for(user_key).exists()

    def enroll_user(self, user_key: str, images_b64: list[str], overwrite: bool = True) -> int:
        self._ensure_runtime_available()
        if not isinstance(images_b64, list) or not images_b64:
            raise ValueError("Debes enviar una lista de imagenes para entrenar FaceID")

        processed_faces = []
        for image in images_b64:
            frame = self._decode_image(image)
            face_gray = self._extract_primary_face(frame)
            if face_gray is None:
                continue
            processed_faces.append(self._preprocess_face(face_gray))

        if len(processed_faces) < self._min_samples:
            raise ValueError(
                f"No se detectaron suficientes rostros validos. Minimo requerido: {self._min_samples}."
            )

        samples_dir = self._samples_dir_for(user_key)
        if overwrite and samples_dir.exists():
            shutil.rmtree(samples_dir, ignore_errors=True)
        samples_dir.mkdir(parents=True, exist_ok=True)

        for idx, face in enumerate(processed_faces, start=1):
            sample_path = samples_dir / f"sample_{idx:03d}.png"
            cv2.imwrite(str(sample_path), face)

        recognizer = self._create_lbph()
        labels = np.ones(len(processed_faces), dtype=np.int32)
        recognizer.train(processed_faces, labels)
        recognizer.write(str(self._model_path_for(user_key)))
        return len(processed_faces)

    def verify_user(self, user_key: str, image_b64: str) -> FaceVerificationResult:
        self._ensure_runtime_available()

        model_path = self._model_path_for(user_key)
        if not model_path.exists():
            raise FileNotFoundError("No existe perfil FaceID entrenado para este usuario")

        frame = self._decode_image(image_b64)
        face_gray = self._extract_primary_face(frame)
        if face_gray is None:
            return FaceVerificationResult(
                autorizado=False,
                confianza_lbph=None,
                rostros_detectados=0,
            )

        recognizer = self._create_lbph()
        recognizer.read(str(model_path))
        processed = self._preprocess_face(face_gray)
        label, confidence = recognizer.predict(processed)
        authorized = bool(int(label) == 1 and float(confidence) <= self._confidence_threshold)
        return FaceVerificationResult(
            autorizado=authorized,
            confianza_lbph=float(confidence),
            rostros_detectados=1,
        )


faceid_service = FaceIdService()
