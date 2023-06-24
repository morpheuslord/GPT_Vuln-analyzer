import openai
openai.api_key = "__API__KEY__"
model_engine = "text-davinci-003"


def gpt_ai(analyze: str, key: str) -> str:
    try:
        # Prompt about what the quary is all about
        prompt = "do a vulnerability analysis of {} and return a vulnerabilty report in json".format(
            analyze)
        # A structure for the request
        completion = openai.Completion.create(
            engine=model_engine,
            prompt=prompt,
            max_tokens=1024,
            n=1,
            stop=None,
        )
        response = completion.choices[0].text
        return str(response)
    except KeyboardInterrupt:
        print("Bye")
        quit()
