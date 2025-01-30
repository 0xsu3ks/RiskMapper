import openai

openai.api_key = ''

try:
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": "Hello, world!"}],
        max_tokens=5
    )
    print("Response:", response.choices[0].message['content'])
except openai.error.AuthenticationError:
    print("Authentication Error: Check your API key.")
except openai.error.RateLimitError:
    print("Rate Limit Exceeded.")
except openai.error.APIError as e:
    print(f"API Error: {e}")
except openai.error.InvalidRequestError as e:
    print(f"Invalid Request Error: {e}")

