import jwt
import json
import base64
from datetime import datetime
from typing import Optional


class JWTAnalyzer:

    def analyze(self, AIModels, token, openai_api_token: Optional[str], bard_api_token: Optional[str], llama_api_token: Optional[str], llama_endpoint: Optional[str], AI: str) -> str:
        try:
            self.algorithm_used = ""
            self.decoded_payload = ""
            self.expiration_time = ""
            parts = token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid token format. Expected 3 parts.")

            header = json.loads(base64.urlsafe_b64decode(parts[0] + '===').decode('utf-8', 'replace'))
            self.algorithm_used = header.get('alg', 'Unknown Algorithm')
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '===').decode('utf-8', 'replace'))
            self.decoded_payload = payload
            self.claims = {key: value for key, value in payload.items()}
            if 'exp' in payload:
                self.expiration_time = datetime.utcfromtimestamp(payload['exp'])
            self.analysis_result = {
                'Algorithm Used': self.algorithm_used,
                'Decoded Payload': self.decoded_payload,
                'Claims': self.claims,
                'Expiration Time': self.expiration_time
            }
            str_data = str(self.analysis_result)
            match AI:
                case 'openai':
                    try:
                        if openai_api_token is not None:
                            pass
                        else:
                            raise ValueError("KeyNotFound: Key Not Provided")
                        response = AIModels.gpt_ai(str_data, openai_api_token)
                    except KeyboardInterrupt:
                        print("Bye")
                        quit()
                case 'bard':
                    try:
                        if bard_api_token is not None:
                            pass
                        else:
                            raise ValueError("KeyNotFound: Key Not Provided")
                        response = AIModels.BardAI(bard_api_token, str_data)
                    except KeyboardInterrupt:
                        print("Bye")
                        quit()
                case 'llama':
                    try:
                        response = AIModels.llama_AI(str_data, "local", llama_api_token, llama_endpoint)
                    except KeyboardInterrupt:
                        print("Bye")
                        quit()
                case 'llama-api':
                    try:
                        response = AIModels.Llama_AI(str_data, "runpod", llama_api_token, llama_endpoint)
                    except KeyboardInterrupt:
                        print("Bye")
                        quit()
            final_data = str(response)
            return final_data
        except jwt.ExpiredSignatureError:
            self.analysis_result = {'Error': 'Token has expired.'}
        except jwt.InvalidTokenError as e:
            self.analysis_result = {'Error': f'Invalid token: {e}'}
