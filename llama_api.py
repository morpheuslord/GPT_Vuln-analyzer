import os
import fire
from enum import Enum
from threading import Thread
from transformers import AutoModelForCausalLM, AutoTokenizer
from auto_gptq import AutoGPTQForCausalLM
from llama_cpp import Llama
from huggingface_hub import hf_hub_download
from transformers import TextIteratorStreamer
from flask import Flask, request, jsonify


BOS, EOS = "<s>", "</s>"
E_INST = "[/INST]"
B_SYS, E_SYS = "<<SYS>>\n", "\n<</SYS>>\n\n"
DEFAULT_SYSTEM_PROMPT = """\
You are a helpful, respectful and honest cybersecurity analyst. Being a security analyst you must scrutanize the details provided to ensure it is usable for penitration testing. Please ensure that your responses are socially unbiased and positive in nature.
If a question does not make any sense, or is not factually coherent, explain why instead of answering something not correct. If you don't know the answer to a question, please don't share false information."""


def format_to_llama_chat_style(user_instructions, history) -> str:
    B_INST = f"[INST]{user_instructions}"
    prompt = ""
    for i, dialog in enumerate(history[:-1]):
        instruction, response = dialog[0], dialog[1]
        if i == 0:
            instruction = f"{B_SYS}{DEFAULT_SYSTEM_PROMPT}{E_SYS}" + instruction
        else:
            prompt += BOS
        prompt += f"{B_INST} {instruction.strip()} {E_INST} {response.strip()} " + EOS

    new_instruction = history[-1][0].strip()
    if len(history) > 1:
        prompt += BOS
    else:
        new_instruction = f"{B_SYS}{DEFAULT_SYSTEM_PROMPT}{E_SYS}" + \
            new_instruction

    prompt += f"{B_INST} {new_instruction} {E_INST}"
    return prompt


class Model_Type(Enum):
    gptq = 1
    ggml = 2
    full_precision = 3


def get_model_type(model_name):
    if "gptq" in model_name.lower():
        return Model_Type.gptq
    elif "ggml" in model_name.lower():
        return Model_Type.ggml
    else:
        return Model_Type.full_precision


def create_folder_if_not_exists(folder_path):
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)


def initialize_gpu_model_and_tokenizer(model_name, model_type):
    if model_type == Model_Type.gptq:
        model = AutoGPTQForCausalLM.from_quantized(
            model_name, device_map="auto", use_safetensors=True,
            use_triton=False)
        tokenizer = AutoTokenizer.from_pretrained(model_name)
    else:
        model = AutoModelForCausalLM.from_pretrained(
            model_name, device_map="auto", token=True)
        tokenizer = AutoTokenizer.from_pretrained(model_name, token=True)
    return model, tokenizer


def init_auto_model_and_tokenizer(model_name, model_type, file_name=None):
    model_type = get_model_type(model_name)

    if Model_Type.ggml == model_type:
        models_folder = "./models"
        create_folder_if_not_exists(models_folder)
        file_path = hf_hub_download(
            repo_id=model_name, filename=file_name, local_dir=models_folder)
        model = Llama(file_path, n_ctx=4096)
        tokenizer = None
    else:
        model, tokenizer = initialize_gpu_model_and_tokenizer(
            model_name, model_type=model_type)
    return model, tokenizer


app = Flask(__name__)


@app.route('/api/chatbot', methods=['POST'])
def chatbot_api():
    data = request.json
    user_instruction = data['user_instruction']
    user_message = data['user_message']
    model_name = data['model_name']
    file_name = data.get('file_name')
    is_chat_model = 'chat' in model_name.lower()
    model_type = get_model_type(model_name)

    if model_type == Model_Type.ggml:
        assert file_name is not None, """
        When model_name is provided for a GGML quantized model, file_name argument must also be provided."""

    model, tokenizer = init_auto_model_and_tokenizer(
        model_name, model_type, file_name)

    if is_chat_model:
        instruction = format_to_llama_chat_style(user_instruction, [[user_message, None]])
    else:
        instruction = user_message

    history = [[user_message, None]]

    response = generate_response(
        model, tokenizer, instruction, history, model_type)
    return jsonify({'bot_response': response})


def generate_response(model, tokenizer, instruction, history, model_type):
    response = ""

    kwargs = dict(temperature=0.6, top_p=0.9)
    if model_type == Model_Type.ggml:
        kwargs["max_tokens"] = 512
        for chunk in model(prompt=instruction, stream=True, **kwargs):
            token = chunk["choices"][0]["text"]
            response += token

    else:
        streamer = TextIteratorStreamer(
            tokenizer, skip_prompt=True, Timeout=5)
        inputs = tokenizer(instruction, return_tensors="pt").to(model.device)
        kwargs["max_new_tokens"] = 512
        kwargs["input_ids"] = inputs["input_ids"]
        kwargs["streamer"] = streamer
        thread = Thread(target=model.generate, kwargs=kwargs)
        thread.start()

        for token in streamer:
            response += token

    return response


def run_app(port):
    app.run(port=port)


if __name__ == '__main__':
    fire.Fire(run_app(5000))
