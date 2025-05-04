"""
Knowledge base component for the Security Agent.
Handles RAG functionality for security-related information.
"""
import os
from typing import List, Optional
import shutil

from langchain_core.documents import Document
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_chroma import Chroma

# Import settings from config module
from backend.config.settings import CHROMA_DIR

class SecurityKnowledgeBase:
    """
    A RAG-based knowledge base for security-related information including:
    - CVE details
    - Security best practices
    - Vulnerability mitigation strategies
    - Organizational security policies
    """
    
    def __init__(self, 
                 model_name: str = "gpt-3.5-turbo", 
                 temperature: float = 0.0,
                 api_key: Optional[str] = None,
                 collection_name: str = "security_knowledge"):
        # Initialize the LLM with API key from environment variable if not provided
        api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.llm = ChatOpenAI(model_name=model_name, temperature=temperature, api_key=api_key)
        
        # Initialize embeddings with API key
        self.embeddings = OpenAIEmbeddings(api_key=api_key)
        
        # Store collection name
        self.collection_name = collection_name
        
        # Initialize vector store
        # This will be populated later with security data
        self._initialize_vector_store()
        
    def _initialize_vector_store(self):
        """Initialize or load the vector store from disk"""
        try:
            # Try to create/load the vector store with an explicit collection name
            from chromadb import PersistentClient
            client = PersistentClient(path=CHROMA_DIR)
            
            self.vectorstore = Chroma(
                persist_directory=CHROMA_DIR,
                embedding_function=self.embeddings,
                collection_name=self.collection_name,
                client=client
            )
            print(f"Loaded/created vector store with collection name: {self.collection_name}")
            
        except Exception as e:
            print(f"Error initializing vector store: {e}")
            print("Attempting to recreate the vector store...")
            
            try:
                # If there's an existing directory and it's causing issues, try to remove it
                if os.path.exists(CHROMA_DIR):
                    # Only remove the contents, not the directory itself
                    for item in os.listdir(CHROMA_DIR):
                        item_path = os.path.join(CHROMA_DIR, item)
                        if os.path.isdir(item_path):
                            shutil.rmtree(item_path)
                        else:
                            os.remove(item_path)
                    print(f"Cleared contents of {CHROMA_DIR}")
                
                # Create a fresh vector store
                from chromadb import PersistentClient
                client = PersistentClient(path=CHROMA_DIR)
                
                self.vectorstore = Chroma(
                    persist_directory=CHROMA_DIR,
                    embedding_function=self.embeddings,
                    collection_name=self.collection_name,
                    client=client
                )
                print(f"Successfully recreated vector store with collection name: {self.collection_name}")
                
            except Exception as e2:
                print(f"Failed to recreate vector store: {e2}")
                # Fall back to in-memory vector store to prevent the application from crashing
                self.vectorstore = Chroma(
                    embedding_function=self.embeddings,
                    collection_name=self.collection_name
                )
                print("Using in-memory vector store as fallback")
    
    def add_documents(self, documents: List[Document]):
        """Add documents to the knowledge base"""
        self.vectorstore.add_documents(documents)
        # Data is automatically persisted when using PersistentClient
        print(f"Added {len(documents)} documents to the knowledge base")
    
    def get_retriever(self, search_type: str = "similarity", k: int = 5):
        """Get a retriever from the vector store"""
        return self.vectorstore.as_retriever(
            search_type=search_type,
            search_kwargs={"k": k}
        )
    
    def create_rag_chain(self):
        """Create a basic RAG chain for answering security-related queries"""
        retriever = self.get_retriever()
        
        template = """You are a security expert assistant focused on helping identify and mitigate vulnerabilities.
        Use the following pieces of context to answer the question at the end. 
        If you don't know the answer, just say that you don't know, don't try to make up an answer.
        
        Context:
        {context}
        
        Question: {question}
        """
        
        prompt = ChatPromptTemplate.from_template(template)
        
        chain = (
            {"context": retriever, "question": RunnablePassthrough()}
            | prompt
            | self.llm
            | StrOutputParser()
        )
        
        return chain