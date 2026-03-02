from __future__ import annotations

import base64
import json
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
    motivo_denegacion: str = ""
    similitud_maxima: Optional[float] = None
    similitud_topk: Optional[float] = None
    coincidencias: int = 0
    umbral_similitud: Optional[float] = None


class FaceIdService:
    @staticmethod
    def _read_float_env(name: str, default: float) -> float:
        raw = os.getenv(name, "").strip()
        if not raw:
            return float(default)
        try:
            return float(raw)
        except ValueError:
            return float(default)

    @staticmethod
    def _read_int_env(name: str, default: int) -> int:
        raw = os.getenv(name, "").strip()
        if not raw:
            return int(default)
        try:
            return int(raw)
        except ValueError:
            return int(default)

    @staticmethod
    def _read_str_env(name: str, default: str) -> str:
        raw = os.getenv(name, "").strip()
        return raw or default

    def __init__(self) -> None:
        base_path = Path(__file__).resolve().parents[1]
        self._samples_path = Path(
            os.getenv("FACEID_SAMPLES_DIR", str(base_path / "faceid_data"))
        )
        self._models_path = Path(
            os.getenv("FACEID_MODELS_DIR", str(base_path / "faceid_models"))
        )
        self._face_size = (160, 160)
        self._vector_face_size = max(24, self._read_int_env("FACEID_VECTOR_FACE_SIZE", 64))
        self._confidence_threshold = max(
            0.0, self._read_float_env("FACEID_CONFIDENCE_THRESHOLD", 85.0)
        )
        self._min_similarity_threshold = min(
            0.98, max(0.0, self._read_float_env("FACEID_MIN_SIMILARITY_THRESHOLD", 0.68))
        )
        self._min_match_count = max(1, self._read_int_env("FACEID_MIN_MATCH_COUNT", 2))
        self._topk_matches = max(1, self._read_int_env("FACEID_TOPK_MATCHES", 3))
        self._liveness_blur_threshold = max(
            0.0, self._read_float_env("FACEID_LIVENESS_BLUR_THRESHOLD", 45.0)
        )
        # Modos soportados:
        # - off: desactiva el chequeo liveness por blur
        # - warn: registra alerta pero no bloquea login
        # - enforce: bloquea login cuando blur < threshold
        self._liveness_mode = self._read_str_env("FACEID_LIVENESS_MODE", "enforce").lower()
        if self._liveness_mode not in {"off", "warn", "enforce"}:
            self._liveness_mode = "enforce"
        self._min_samples = max(1, self._read_int_env("FACEID_MIN_SAMPLES", 8))

        self._samples_path.mkdir(parents=True, exist_ok=True)
        self._models_path.mkdir(parents=True, exist_ok=True)

        self._haar_detector = None
        if cv2 is not None:
            self._haar_detector = cv2.CascadeClassifier(
                cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
            )

    def _check_liveness_blur(self, face_gray) -> bool:
        if cv2 is None:
            raise RuntimeError("FaceID requiere OpenCV para validar liveness.")
        varianza = cv2.Laplacian(face_gray, cv2.CV_64F).var()
        return varianza > self._liveness_blur_threshold

    def _should_enforce_liveness(self) -> bool:
        return self._liveness_mode == "enforce"

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

    def _profile_path_for(self, user_key: str) -> Path:
        safe_user = self._normalize_user_key(user_key)
        return self._models_path / f"{safe_user}.profile.json"

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

    def _face_to_vector(self, face_gray):
        face_small = cv2.resize(face_gray, (self._vector_face_size, self._vector_face_size))
        vector = face_small.astype(np.float32).reshape(-1)
        vector -= float(vector.mean())
        std = float(vector.std())
        if std > 1e-6:
            vector /= std
        norm = float(np.linalg.norm(vector))
        if norm > 1e-6:
            vector /= norm
        return vector

    def _build_similarity_profile(self, processed_faces: list) -> dict:
        vectors = [self._face_to_vector(face) for face in processed_faces]
        if not vectors:
            raise ValueError("No hay vectores faciales para construir perfil FaceID")

        pairwise_similarities: list[float] = []
        total = len(vectors)
        for i in range(total):
            for j in range(i + 1, total):
                pairwise_similarities.append(float(np.dot(vectors[i], vectors[j])))

        learned_threshold = self._min_similarity_threshold
        if pairwise_similarities:
            p10 = float(np.percentile(pairwise_similarities, 10))
            learned_threshold = max(self._min_similarity_threshold, min(0.98, p10 - 0.05))
        # Evita umbrales extremadamente altos que luego causan rechazos al mismo usuario.
        learned_threshold = min(learned_threshold, self._min_similarity_threshold + 0.10)

        min_match_count = min(total, max(1, self._min_match_count))
        topk = min(total, max(self._topk_matches, min_match_count))

        return {
            "similarityThreshold": float(learned_threshold),
            "minMatchCount": int(min_match_count),
            "topK": int(topk),
            "vectors": [vector.astype(np.float32).tolist() for vector in vectors],
        }

    def _save_similarity_profile(self, user_key: str, profile: dict) -> None:
        profile_path = self._profile_path_for(user_key)
        profile_path.write_text(json.dumps(profile, ensure_ascii=True), encoding="utf-8")

    def _load_similarity_profile(self, user_key: str) -> Optional[dict]:
        profile_path = self._profile_path_for(user_key)
        if not profile_path.exists():
            return None

        try:
            payload = json.loads(profile_path.read_text(encoding="utf-8"))
        except Exception:
            return None

        vectors_raw = payload.get("vectors", [])
        if not isinstance(vectors_raw, list) or not vectors_raw:
            return None

        vectors = []
        for raw in vectors_raw:
            if not isinstance(raw, list) or not raw:
                continue
            vector = np.asarray(raw, dtype=np.float32)
            norm = float(np.linalg.norm(vector))
            if norm > 1e-6:
                vector = vector / norm
            vectors.append(vector)
        if not vectors:
            return None

        threshold_raw = payload.get("similarityThreshold", self._min_similarity_threshold)
        min_match_raw = payload.get("minMatchCount", self._min_match_count)
        topk_raw = payload.get("topK", self._topk_matches)
        try:
            threshold = float(threshold_raw)
        except Exception:
            threshold = self._min_similarity_threshold
        try:
            min_match = int(min_match_raw)
        except Exception:
            min_match = self._min_match_count
        try:
            topk = int(topk_raw)
        except Exception:
            topk = self._topk_matches

        threshold = min(0.98, max(self._min_similarity_threshold, threshold))
        min_match = min(len(vectors), max(1, min_match))
        topk = min(len(vectors), max(1, topk))
        # Compatibilidad: perfiles anteriores pudieron guardar exigencias muy estrictas.
        threshold = min(threshold, self._min_similarity_threshold + 0.10)
        min_match = min(min_match, max(1, self._min_match_count))
        topk = max(topk, min_match)

        return {
            "similarityThreshold": threshold,
            "minMatchCount": min_match,
            "topK": topk,
            "vectors": vectors,
        }

    def _load_processed_samples(self, user_key: str) -> list:
        samples_dir = self._samples_dir_for(user_key)
        if not samples_dir.exists():
            return []

        processed_faces = []
        for sample_path in sorted(samples_dir.glob("*.png")):
            face = cv2.imread(str(sample_path), cv2.IMREAD_GRAYSCALE)
            if face is None:
                continue
            if tuple(face.shape[:2][::-1]) != self._face_size:
                face = cv2.resize(face, self._face_size)
            processed_faces.append(face)
        return processed_faces

    def _load_or_build_similarity_profile(self, user_key: str) -> dict:
        loaded = self._load_similarity_profile(user_key)
        if loaded is not None:
            return loaded

        processed_faces = self._load_processed_samples(user_key)
        if not processed_faces:
            raise FileNotFoundError("No hay muestras faciales registradas para este usuario")

        profile = self._build_similarity_profile(processed_faces)
        self._save_similarity_profile(user_key, profile)
        return self._load_similarity_profile(user_key) or {
            "similarityThreshold": profile["similarityThreshold"],
            "minMatchCount": profile["minMatchCount"],
            "topK": profile["topK"],
            "vectors": [np.asarray(v, dtype=np.float32) for v in profile["vectors"]],
        }

    @staticmethod
    def _topk_average(values: list[float], k: int) -> float:
        if not values:
            return 0.0
        k = max(1, min(k, len(values)))
        top_values = sorted(values, reverse=True)[:k]
        return float(sum(top_values) / len(top_values))

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
        profile = self._build_similarity_profile(processed_faces)
        self._save_similarity_profile(user_key, profile)
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
                motivo_denegacion="no_face_detected",
            )

        liveness_ok = self._check_liveness_blur(face_gray) if self._liveness_mode != "off" else True
        if not liveness_ok:
            print(
                "[ALERTA] Posible ataque de presentacion por blur "
                f"(threshold={self._liveness_blur_threshold}, mode={self._liveness_mode})."
            )
            if self._should_enforce_liveness():
                return FaceVerificationResult(
                    autorizado=False,
                    confianza_lbph=None,
                    rostros_detectados=1,
                    motivo_denegacion="liveness_blur_failed",
                )

        recognizer = self._create_lbph()
        recognizer.read(str(model_path))
        processed = self._preprocess_face(face_gray)
        profile = self._load_or_build_similarity_profile(user_key)
        probe_vector = self._face_to_vector(processed)
        similarities = [float(np.dot(probe_vector, ref)) for ref in profile["vectors"]]
        similarity_best = max(similarities) if similarities else 0.0
        similarity_topk = self._topk_average(similarities, int(profile["topK"]))
        similarity_threshold = float(profile["similarityThreshold"])
        min_match_count = int(profile["minMatchCount"])
        similarity_matches = sum(1 for value in similarities if value >= similarity_threshold)

        label, confidence = recognizer.predict(processed)
        lbph_authorized = bool(int(label) == 1 and float(confidence) <= self._confidence_threshold)
        lbph_near = bool(int(label) == 1 and float(confidence) <= (self._confidence_threshold + 12.0))
        similarity_authorized = bool(
            similarity_best >= similarity_threshold
            and similarity_topk >= max(0.0, similarity_threshold - 0.03)
            and similarity_matches >= min_match_count
        )
        similarity_strong = bool(similarity_best >= min(0.99, similarity_threshold + 0.04))
        authorized = bool(similarity_authorized and (lbph_authorized or lbph_near or similarity_strong))
        if not authorized:
            print(
                "[FACEID] Denegado por reconocimiento "
                f"(label={label}, confidence={float(confidence):.2f}, "
                f"threshold={self._confidence_threshold}, "
                f"sim_best={similarity_best:.3f}, sim_topk={similarity_topk:.3f}, "
                f"sim_matches={similarity_matches}/{min_match_count}, "
                f"sim_threshold={similarity_threshold:.3f}, "
                f"lbph_ok={lbph_authorized}, lbph_near={lbph_near}, sim_ok={similarity_authorized})."
            )
            return FaceVerificationResult(
                autorizado=False,
                confianza_lbph=float(confidence),
                rostros_detectados=1,
                motivo_denegacion="face_mismatch",
                similitud_maxima=similarity_best,
                similitud_topk=similarity_topk,
                coincidencias=similarity_matches,
                umbral_similitud=similarity_threshold,
            )
        return FaceVerificationResult(
            autorizado=True,
            confianza_lbph=float(confidence),
            rostros_detectados=1,
            similitud_maxima=similarity_best,
            similitud_topk=similarity_topk,
            coincidencias=similarity_matches,
            umbral_similitud=similarity_threshold,
        )
