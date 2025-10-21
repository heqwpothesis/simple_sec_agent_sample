#!/usr/bin/env python3
"""
Example usage of the IDOR Detection Agent classes

This script demonstrates how to use the three agent classes programmatically.
"""

from simple_agent import SimpleIDORAgent
from openapi_agent import OpenAPIIDORAgent  
from enhanced_agent import EnhancedIDORAgent

def demo_simple_agent():
    """Demonstrate SimpleIDORAgent usage"""
    print("\n=== Simple IDOR Agent Demo ===")
    
    # Create agent with custom parameters
    agent = SimpleIDORAgent(
        base_url="http://127.0.0.1:5005",
        username="bob",
        password="bob123"
    )
    
    print("Agent created. Would run with: agent.run()")
    # result = agent.run()  # Uncomment to actually run
    
def demo_openapi_agent():
    """Demonstrate OpenAPIIDORAgent usage"""
    print("\n=== OpenAPI IDOR Agent Demo ===")
    
    # Create agent with custom parameters
    agent = OpenAPIIDORAgent(
        base_url="http://127.0.0.1:5005",
        username="bob", 
        password="bob123"
    )
    
    print("Agent created. Would run with: agent.run()")
    # result = agent.run()  # Uncomment to actually run

def demo_enhanced_agent():
    """Demonstrate EnhancedIDORAgent usage"""
    print("\n=== Enhanced IDOR Agent Demo ===")
    
    # Create agent with custom parameters
    agent = EnhancedIDORAgent(
        base_url="http://127.0.0.1:5005",
        username="bob",
        password="bob123",
        verbose=True
    )
    
    print("Agent created. Would run with: agent.run()")
    # result = agent.run()  # Uncomment to actually run

if __name__ == "__main__":
    print("IDOR Detection Agent Class Usage Examples")
    print("=" * 50)
    
    demo_simple_agent()
    demo_openapi_agent() 
    demo_enhanced_agent()
    
    print("\n=== Summary ===")
    print("All three agents are now available as classes:")
    print("1. SimpleIDORAgent - Basic IDOR detection")
    print("2. OpenAPIIDORAgent - OpenAPI-driven detection")  
    print("3. EnhancedIDORAgent - Comprehensive detection with advanced features")
    print("\nEach can be used both as:")
    print("- Python classes: agent = SimpleIDORAgent(); result = agent.run()")
    print("- CLI scripts: python simple_agent.py --base-url http://target --username user")