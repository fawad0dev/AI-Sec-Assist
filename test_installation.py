#!/usr/bin/env python3
"""
Installation Test Script
Verifies that all dependencies and modules are properly installed
"""
import sys
import os

def test_imports():
    """Test if all required modules can be imported"""
    print("Testing module imports...")
    
    tests = [
        ("customtkinter", "CustomTkinter GUI framework"),
        ("requests", "HTTP requests library"),
        ("psutil", "System monitoring library"),
    ]
    
    failed = []
    for module, description in tests:
        try:
            __import__(module)
            print(f"✓ {module:20s} - {description}")
        except ImportError as e:
            print(f"✗ {module:20s} - FAILED: {str(e)}")
            failed.append(module)
    
    return len(failed) == 0

def test_project_structure():
    """Test if project structure is correct"""
    print("\nTesting project structure...")
    
    required_paths = [
        "src/scanners/log_scanner.py",
        "src/scanners/network_analyzer.py",
        "src/scanners/file_scanner.py",
        "src/scanners/registry_scanner.py",
        "src/ai/ollama_client.py",
        "src/gui/main_gui.py",
        "src/utils/config_manager.py",
        "main.py",
    ]
    
    all_found = True
    for path in required_paths:
        full_path = os.path.join(os.path.dirname(__file__), path)
        if os.path.exists(full_path):
            print(f"✓ {path}")
        else:
            print(f"✗ {path} - NOT FOUND")
            all_found = False
    
    return all_found

def test_ollama_connection():
    """Test Ollama connection"""
    print("\nTesting Ollama connection...")
    
    try:
        import requests
        response = requests.get("http://localhost:11434/", timeout=2)
        if response.status_code == 200:
            print("✓ Ollama is running and accessible")
            return True
        else:
            print("✗ Ollama responded with unexpected status code")
            return False
    except requests.exceptions.ConnectionError:
        print("⚠ Ollama is not running (this is optional)")
        print("  Start Ollama with: ollama serve")
        return True  # Don't fail, just warn
    except Exception as e:
        print(f"⚠ Could not test Ollama connection: {str(e)}")
        return True  # Don't fail, just warn

def main():
    """Run all tests"""
    print("=" * 60)
    print("AI Security Assistant - Installation Test")
    print("=" * 60)
    print()
    
    results = []
    
    # Test imports
    results.append(("Module Imports", test_imports()))
    
    # Test project structure
    results.append(("Project Structure", test_project_structure()))
    
    # Test Ollama connection
    results.append(("Ollama Connection", test_ollama_connection()))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    for test_name, passed in results:
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"{test_name:20s}: {status}")
    
    all_passed = all(result[1] for result in results)
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✓ All tests passed! You can run the application with:")
        print("  python main.py")
    else:
        print("✗ Some tests failed. Please install missing dependencies:")
        print("  pip install -r requirements.txt")
    print("=" * 60)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
