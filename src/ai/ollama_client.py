"""
Ollama AI Integration Module
Integrates with Ollama for local AI model inference
"""
import requests
import json
from typing import Dict, List, Optional


class OllamaClient:
    """Client for interacting with Ollama API"""
    
    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        
    def is_available(self) -> bool:
        """Check if Ollama is running and accessible"""
        try:
            response = requests.get(f"{self.base_url}/", timeout=2)
            return response.status_code == 200
        except:
            return False
    
    def list_models(self) -> List[Dict]:
        """
        Get list of available models
        
        Returns:
            List of model information
        """
        try:
            response = requests.get(f"{self.api_url}/tags", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('models', [])
        except Exception as e:
            print(f"Error listing models: {e}")
        return []
    
    def generate(self, model: str, prompt: str, system_prompt: Optional[str] = None,
                stream: bool = False, temperature: float = 0.1) -> str:
        """
        Generate response from Ollama model
        
        Args:
            model: Model name (e.g., 'llama2', 'mistral')
            prompt: User prompt
            system_prompt: System prompt for context
            stream: Whether to stream the response
            temperature: Lower = more focused/deterministic (0.0-1.0)
            
        Returns:
            Generated text response
        """
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": stream,
            "options": {
                "temperature": temperature,  # Low temperature for security accuracy
                "top_p": 0.9,
                "top_k": 40,
            }
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
        try:
            response = requests.post(
                f"{self.api_url}/generate",
                json=payload,
                timeout=120
            )
            
            if response.status_code == 200:
                if stream:
                    # Handle streaming response
                    full_response = ""
                    for line in response.iter_lines():
                        if line:
                            data = json.loads(line)
                            if 'response' in data:
                                full_response += data['response']
                    return full_response
                else:
                    data = response.json()
                    return data.get('response', '')
            else:
                return f"Error: {response.status_code} - {response.text}"
                
        except requests.exceptions.Timeout:
            return "Error: Request timed out. The model might be too large or the query too complex."
        except Exception as e:
            return f"Error generating response: {str(e)}"
    
    def chat(self, model: str, messages: List[Dict], temperature: float = 0.1) -> str:
        """
        Chat with model using conversation format
        
        Args:
            model: Model name
            messages: List of message dicts with 'role' and 'content'
            temperature: Response randomness (0.0-1.0)
            
        Returns:
            Generated response
        """
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
            }
        }
        
        try:
            response = requests.post(
                f"{self.api_url}/chat",
                json=payload,
                timeout=120
            )
            
            if response.status_code == 200:
                data = response.json()
                message = data.get('message', {})
                return message.get('content', '')
            else:
                return f"Error: {response.status_code}"
                
        except Exception as e:
            return f"Error: {str(e)}"


class SecurityAI:
    """AI assistant specialized for security analysis"""
    
    SYSTEM_PROMPT = """You are a cybersecurity expert assistant. Your role is to:
1. Analyze security scan results and provide accurate, factual assessments
2. Identify genuine security threats and vulnerabilities
3. Provide actionable remediation steps
4. NEVER speculate or hallucinate information
5. If you're unsure, say so clearly
6. Focus on facts from the provided data
7. Prioritize threats by severity
8. Provide specific, technical recommendations

Always base your responses strictly on the information provided. Do not make assumptions about threats that aren't clearly indicated by the data."""
    
    def __init__(self, ollama_client: OllamaClient, model: str = "llama2"):
        self.client = ollama_client
        self.model = model
        self.conversation_history = []
        
    def analyze_scan_results(self, scan_type: str, results: str) -> str:
        """
        Analyze security scan results with AI
        
        Args:
            scan_type: Type of scan (log, network, file, registry)
            results: Scan results as text
            
        Returns:
            AI analysis and recommendations
        """
        prompt = f"""Analyze the following {scan_type} scan results and provide:
1. Summary of key findings
2. Risk assessment (Critical/High/Medium/Low)
3. Specific threats identified
4. Recommended actions to address issues

IMPORTANT: Base your analysis ONLY on the data provided. Do not speculate about threats not evident in the results.

Scan Results:
{results[:5000]}  

Provide a clear, structured analysis."""

        response = self.client.generate(
            model=self.model,
            prompt=prompt,
            system_prompt=self.SYSTEM_PROMPT,
            temperature=0.1  # Low temperature for factual responses
        )
        
        return response
    
    def answer_security_question(self, question: str, context: str = "") -> str:
        """
        Answer security-related questions
        
        Args:
            question: User's security question
            context: Optional context from recent scans
            
        Returns:
            AI response
        """
        if context:
            prompt = f"""Context from recent scans:
{context[:2000]}

User question: {question}

Provide a helpful answer based on the context and general security best practices."""
        else:
            prompt = f"""User question: {question}

Provide helpful security guidance based on best practices. If the question requires specific system information you don't have, clearly state what information would be needed."""
        
        response = self.client.generate(
            model=self.model,
            prompt=prompt,
            system_prompt=self.SYSTEM_PROMPT,
            temperature=0.2
        )
        
        return response
    
    def get_remediation_steps(self, threat_description: str) -> str:
        """
        Get detailed remediation steps for a specific threat
        
        Args:
            threat_description: Description of the security threat
            
        Returns:
            Step-by-step remediation guide
        """
        prompt = f"""Provide detailed, step-by-step remediation instructions for the following security threat:

Threat: {threat_description}

Include:
1. Immediate actions to contain the threat
2. Investigation steps
3. Remediation procedures
4. Prevention measures for the future

Be specific and practical."""

        response = self.client.generate(
            model=self.model,
            prompt=prompt,
            system_prompt=self.SYSTEM_PROMPT,
            temperature=0.1
        )
        
        return response
    
    def chat_conversation(self, user_message: str) -> str:
        """
        Have a conversation with the AI assistant
        
        Args:
            user_message: User's message
            
        Returns:
            AI response
        """
        # Add user message to history
        self.conversation_history.append({
            "role": "user",
            "content": user_message
        })
        
        # Limit conversation history to last 10 messages
        if len(self.conversation_history) > 10:
            self.conversation_history = self.conversation_history[-10:]
        
        # Add system prompt as first message if not present
        messages = [{"role": "system", "content": self.SYSTEM_PROMPT}]
        messages.extend(self.conversation_history)
        
        response = self.client.chat(
            model=self.model,
            messages=messages,
            temperature=0.2
        )
        
        # Add assistant response to history
        self.conversation_history.append({
            "role": "assistant",
            "content": response
        })
        
        return response
    
    def clear_conversation(self):
        """Clear conversation history"""
        self.conversation_history = []
