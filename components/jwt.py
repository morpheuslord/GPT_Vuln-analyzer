import jwt
import base64
from datetime import datetime
from components.models import JWT_AI_MODEL


class JWTAnalyzer:
    def __init__(self):
        self.AI_models = JWT_AI_MODEL()
        self.model_map = {
            'openai': self.call_openai_model,
            'bard': self.call_bard_model,
            'llama': self.call_llama_model,
            'llama-api': self.call_llama_api_model
        }

    @staticmethod
    def base64_url_decode(input_str):
        padding = '=' * (4 - (len(input_str) % 4))
        return base64.urlsafe_b64decode(input_str + padding).decode('utf-8', 'replace')

    @staticmethod
    def decode_jwt(token):
        try:
            decoded = jwt.decode(token, algorithms=["HS256"], options={"verify_signature": False})
            return decoded
        except jwt.ExpiredSignatureError:
            return {'Error': 'Token has expired.'}
        except jwt.InvalidTokenError as e:
            return {'Error': f'Invalid token: {e}'}

    def analyze(self, token, **api_tokens):
        decoded_payload = self.decode_jwt(token)
        if 'Error' in decoded_payload:
            return decoded_payload

        algorithm_used = decoded_payload.get('alg', 'Unknown Algorithm')
        expiration_time = datetime.utcfromtimestamp(decoded_payload['exp']) if 'exp' in decoded_payload else ''

        analysis_result = {
            'Algorithm Used': algorithm_used,
            'Decoded Payload': decoded_payload,
            'Claims': decoded_payload,
            'Expiration Time': expiration_time
        }

        return self.call_ai_model(api_tokens['AI'], str(analysis_result), **api_tokens)

    def call_ai_model(self, ai_name, data, **tokens):
        ai_function = self.model_map.get(ai_name)
        if ai_function and tokens.get(f'{ai_name}_api_token'):
            return ai_function(data, tokens[f'{ai_name}_api_token'], tokens.get(f'{ai_name}_endpoint'))
        else:
            return "Error: AI model or token not provided."

    def call_openai_model(self, data, token, _):
        return self.AI_models.gpt_ai(data, token)

    def call_bard_model(self, data, token, _):
        return self.AI_models.BardAI(token, data)

    def call_llama_model(self, data, token, endpoint):
        return self.AI_models.llama_AI(data, "local", token, endpoint)

    def call_llama_api_model(self, data, token, endpoint):
        return self.AI_models.Llama_AI(data, "runpod", token, endpoint)
