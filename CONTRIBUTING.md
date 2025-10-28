# Contributing to NetScan

First off, thank you for considering contributing to NetScan! It's people like you that make NetScan such a great tool.

## Code of Conduct

This project and everyone participating in it is governed by common sense and mutual respect. By participating, you are expected to uphold this standard.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When you are creating a bug report, please include as many details as possible:

* **Use a clear and descriptive title** for the issue
* **Describe the exact steps to reproduce the problem**
* **Provide specific examples** to demonstrate the steps
* **Describe the behavior you observed** after following the steps
* **Explain which behavior you expected to see instead and why**
* **Include screenshots** if relevant
* **Include your environment details** (OS, Python version, etc.)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

* **Use a clear and descriptive title**
* **Provide a detailed description of the suggested enhancement**
* **Provide specific examples to demonstrate the steps or usage**
* **Describe the current behavior** and **explain the behavior you expected to see**
* **Explain why this enhancement would be useful**

### Pull Requests

* Fill in the required template
* Follow the Python style guide (PEP 8)
* Include docstrings for all functions, classes, and modules
* Update documentation if needed
* Add tests if applicable
* Ensure all tests pass before submitting

## Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/NetScan.git
   cd NetScan
   ```

3. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install flake8 pylint  # For linting
   ```

5. Create a branch for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Style Guidelines

### Python Style Guide

* Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
* Use 4 spaces for indentation (no tabs)
* Maximum line length is 120 characters
* Use docstrings for all public modules, functions, classes, and methods
* Use type hints where appropriate

### Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line

Example:
```
Add CSV export functionality

- Implement export_to_csv function
- Add tests for CSV export
- Update documentation

Closes #123
```

### Docstring Format

Use Google-style docstrings:

```python
def example_function(param1, param2):
    """
    Brief description of the function.

    More detailed description if needed.

    Args:
        param1 (type): Description of param1
        param2 (type): Description of param2

    Returns:
        type: Description of return value

    Raises:
        ExceptionType: Description of when this exception is raised
    """
    pass
```

## Testing

* Write tests for new functionality
* Ensure existing tests pass
* Run linting before submitting:
  ```bash
  flake8 --max-line-length=120 src/
  ```

## Project Structure

```
NetScan/
├── src/              # Source code
│   ├── app.py        # Main application
│   ├── config.py     # Configuration management
│   ├── export.py     # Export functionality
│   └── ...           # Other modules
├── tests/            # Test files (if any)
├── docs/             # Documentation
├── README.md         # Project README
├── CONTRIBUTING.md   # This file
└── requirements.txt  # Dependencies
```

## Adding New Features

When adding a new feature:

1. **Discuss first**: For major changes, please open an issue first to discuss what you would like to change
2. **Follow existing patterns**: Look at how similar features are implemented
3. **Document your code**: Add docstrings and update README if needed
4. **Add configuration options**: If your feature is configurable, add it to the config module
5. **Handle errors gracefully**: Add proper error handling and user-friendly error messages
6. **Consider security**: Network scanning tools have security implications - be careful

## Security Considerations

When contributing to NetScan, please keep in mind:

* Never commit sensitive information (credentials, API keys, etc.)
* Consider the security implications of network scanning features
* Test features in a safe, controlled environment
* Add appropriate warnings for potentially dangerous operations

## Questions?

Feel free to open an issue with your question or reach out to the maintainers.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

Thank you for contributing to NetScan! 🎉
