"""A dummy Salt Stack module to use during unit testing.

Borrowed strategy from here:
    https://stackoverflow.com/questions/41220803/mock-an-entire-module-in-python
"""

import sys
import types

try:
    from unittest.mock import Mock
except ImportError:
    from mock import Mock

module_name = 'salt'
fake_salt = types.ModuleType(module_name)
sys.modules[module_name] = fake_salt
fake_salt.client = Mock(name=module_name + '.client')
