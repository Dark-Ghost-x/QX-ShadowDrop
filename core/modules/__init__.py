#!/usr/bin/env python3
import os
import importlib
from typing import Dict, Any

from .vulnerability_base import VulnerabilityModule

__all__ = ['VulnerabilityModule']

def load_modules() -> Dict[str, Any]:
    """Dynamically load all modules in this directory"""
    modules = {}
    modules_dir = os.path.dirname(__file__)
    
    for module_file in os.listdir(modules_dir):
        if module_file.endswith('.py') and not module_file.startswith('_'):
            module_name = module_file[:-3]
            try:
                module = importlib.import_module(f'.{module_name}', __name__)
                if hasattr(module, 'Scanner'):
                    modules[module_name] = module
            except ImportError as e:
                print(f"Warning: Failed to import module {module_name}: {e}")
            except Exception as e:
                print(f"Warning: Error loading module {module_name}: {e}")
    
    return modules

try:
    _modules = load_modules()
except Exception as e:
    print(f"Warning: Failed to load modules: {e}")
    _modules = {}
