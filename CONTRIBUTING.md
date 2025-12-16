# Contributing to React2Scan

Thank you for your interest in contributing to React2Scan! We welcome contributions from the community to help make this tool better.

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue in the issue tracker. Be sure to include:

*   A descriptive title.
*   Steps to reproduce the issue.
*   Expected behavior vs. actual behavior.
*   Your environment details (OS, Python version, etc.).

### Suggesting Enhancements

Have an idea for a new feature? We'd love to hear it! Open an issue describing your idea and why it would be useful.

### Pull Requests

1.  **Fork the repository** and create your branch from `main`.
2.  **Install dependencies** and set up your development environment.
    ```bash
    pip install -e .[dev]
    ```
3.  **Make your changes**. Ensure your code follows the project's style (we use `black` and `ruff`).
4.  **Test your changes**. Run existing tests and add new ones if necessary.
5.  **Submit a Pull Request**. Provide a clear description of your changes and reference any related issues.

## Development Setup

1.  Clone your fork:
    ```bash
    git clone https://github.com/YOUR_USERNAME/react2scan.git
    cd react2scan
    ```

2.  Create a virtual environment:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  Install in editable mode:
    ```bash
    pip install -e .
    ```

## Code Style

This project adheres to the following coding standards:

*   **Formatter**: Black
*   **Linter**: Ruff

Please ensure your code is formatted and lint-free before submitting a PR.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
