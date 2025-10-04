from langchain_ollama.llms import OllamaLLM
from langchain_core.prompts import ChatPromptTemplate
from vector import retriever

model = OllamaLLM(model="llama3.2", device="cuda")

template = """
You are an God in Cyber security domain.
You have to give answers based of the data given to you and the question asked by the user.
Your Task will also be to explain the attack path and how the vulnerability can be exploited in simple terms.

Now with the details which will be provided to you, answer the question asked by the user in really simple terms.

Vulnerability description and its solution: {content}

Here is the question about cyber security you need to answer: {question}
"""

prompt = ChatPromptTemplate.from_template(template)

chain = prompt | model

while True:
    question = input("Enter your question (or q to quit): ")
    if question.lower() == "q":
        break

    reviews = retriever.invoke(question)
    result = chain.invoke({
        "content": reviews,
        "question": question,
    })
    print(result)