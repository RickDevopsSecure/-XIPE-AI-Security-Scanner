# Contributing to XIPE

Thanks for your interest in contributing! XIPE is an open source AI security scanner and we welcome contributions of all kinds.

## Before You Start

- All contributions must be for **defensive security purposes only**
- New attack modules must include a corresponding detection/remediation recommendation
- Never include real credentials, API keys, or target data in PRs

## Ways to Contribute

### New Attack Modules
Located in `modules/`. Each module should:
- Inherit from the base module class
- Return a list of `Finding` objects
- Include OWASP category mapping
- Have a clear description and remediation guidance

### Bug Fixes
Open an issue first describing the bug, then submit a PR referencing it.

### Reporting Issues
- Security vulnerabilities: email security@inbest.cloud (do not open public issues)
- Bugs: open a GitHub issue with reproduction steps
- Feature requests: open a GitHub issue with use case description

## Development Setup

```bash
git clone https://github.com/RickDevopsSecure/-XIPE-AI-Security-Scanner.git
cd -XIPE-AI-Security-Scanner
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run against mock server
python mock_server.py &
python main.py --config config.yaml
```

## PR Guidelines

- One feature/fix per PR
- Add tests if applicable
- Update `config.yaml.example` if adding new config options
- Update README if adding new modules or changing behavior

## Code Style

- Python 3.11+
- Follow existing patterns in `modules/`
- Type hints where reasonable
- Keep module independence — modules should not import from each other

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
