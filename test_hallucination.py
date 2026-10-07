from guardrails.hallucination import check_grounding


context = [
    {
        "filename": "company.txt",
        "chunk_index": 0,
        "text": "Our company was founded in 2020.",
    }
]


result = check_grounding(
    question="Which year was our company founded?",
    answer="Our company was founded in 2020.",
    retrieved_documents=context,
)

print("\n========== RESULT ==========")
print(result)
print("============================")