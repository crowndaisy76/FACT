import sys
from langchain_community.chat_models import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough

def load_context(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        print(f"[-] Error: {filepath} 파일을 찾을 수 없습니다.")
        return None

def build_local_rag_chain(context_text):
    try:
        # 답변의 일관성을 높이기 위해 temperature를 0.0으로 고정
        llm = ChatOllama(model="llama3", temperature=0.0)
    except Exception as e:
        print("[-] Ollama 연결 실패. Ollama가 실행 중인지 확인하세요.")
        sys.exit(1)
    
    template = """당신은 CTI 분석가입니다. 반드시 아래 제공된 [보고서] 내용만을 참고하여 '한국어'로 대답하세요. 보고서에 없는 내용은 절대 지어내지 마세요.
    
    [보고서]
    {context}
    
    [질문]
    {question}"""
    
    prompt = ChatPromptTemplate.from_template(template)
    
    chain = (
        {"context": lambda x: context_text, "question": RunnablePassthrough()} 
        | prompt 
        | llm 
        | StrOutputParser()
    )
    
    return chain

def start_chat():
    context_file = "rag_context.txt"
    print("[*] Loading knowledge base...")
    context = load_context(context_file)
    
    if not context:
        return
        
    print("[+] Knowledge base loaded. Connecting to local Ollama model...")
    rag_chain = build_local_rag_chain(context)
    
    print("\n" + "="*50)
    print("🤖 FACT CTI AI Analyst (Local/Ollama) 에 오신 것을 환영합니다.")
    print("   'quit' 또는 'exit'를 입력하면 종료됩니다.")
    print("="*50 + "\n")
    
    while True:
        try:
            user_input = input("\n[Analyst Query] > ")
            if user_input.lower() in ['quit', 'exit']:
                print("시스템을 종료합니다.")
                break
                
            if not user_input.strip():
                continue
                
            print("\n[로컬 AI 모델이 답변을 생성 중입니다. (PC 성능에 따라 시간이 걸릴 수 있습니다)...]")
            
            # [핵심] 사용자 질문 끝에 한국어 답변을 다시 한번 강제함
            augmented_query = user_input + "\n\n(반드시 전문적인 한국어로만 요약해서 대답해줘.)"
            
            print("-" * 50)
            for chunk in rag_chain.stream(augmented_query):
                print(chunk, end="", flush=True)
            print("\n" + "-" * 50)
            
        except KeyboardInterrupt:
            print("\n시스템을 강제 종료합니다.")
            break
        except Exception as e:
            print(f"\n[-] 오류 발생: {e}")

if __name__ == "__main__":
    start_chat()