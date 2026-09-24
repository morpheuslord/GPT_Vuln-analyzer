import base64
from datetime import datetime, timezone
from typing import Any, Dict, Iterable

import jwt

from GVA.ai_providers import AIEngine, AnalysisReport


class JWTAnalyzer:
    @staticmethod
    def base64_url_decode(input_str: str) -> str:
        padding = '=' * (4 - (len(input_str) % 4))
        return base64.urlsafe_b64decode(input_str + padding).decode('utf-8', 'replace')

    @staticmethod
    def decode_jwt(token: str) -> Dict[str, Any]:
        try:
            return jwt.decode(token, algorithms=["HS256"], options={"verify_signature": False})
        except jwt.ExpiredSignatureError:
            return {'Error': 'Token has expired.'}
        except jwt.InvalidTokenError as exc:
            return {'Error': f'Invalid token: {exc}'}

    def analyze(self, token: str, engine: AIEngine, providers: Iterable[str]) -> AnalysisReport:
        decoded_payload = self.decode_jwt(token)
        if 'Error' in decoded_payload:
            return AnalysisReport(scan_type="jwt", errors={"jwt": decoded_payload['Error']})

        # The algorithm lives in the (unverified) header, not the payload.
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError:
            header = {}
        algorithm_used = header.get('alg', 'Unknown Algorithm')

        expiration = ''
        if 'exp' in decoded_payload:
            expiration = datetime.fromtimestamp(decoded_payload['exp'], tz=timezone.utc).isoformat()

        analysis_input = {
            'Algorithm Used': algorithm_used,
            'Header': header,
            'Decoded Payload': decoded_payload,
            'Expiration Time': expiration,
        }
        return engine.run("jwt", str(analysis_input), providers)
