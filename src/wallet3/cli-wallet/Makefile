PYTHON_MAJOR_VERSION=3
PYTHON_MINOR_VERSION=10
PYTHON_VERSION=$(PYTHON_MAJOR_VERSION).$(PYTHON_MINOR_VERSION)
PYTHON_WITH_VERSION=python$(PYTHON_VERSION)
PIP_WITH_VERSION=pip$(PYTHON_VERSION)

all: build

system_dependencies:
	sudo apt install python3.10-venv python3-oxenmq
	$(PIP_WITH_VERSION) install --upgrade pip
	$(PIP_WITH_VERSION) install --upgrade build
	$(PIP_WITH_VERSION) install --upgrade setuptools

build:
	$(PYTHON_WITH_VERSION) -m build
	$(PIP_WITH_VERSION) install --user --editable .

run:
	oxen_wallet_cli

clean:
	find . -type d -name "__pycache__" -exec rm -r {} +
	find . -type d -name "*.egg-info" -exec rm -r {} +
	rm -rf dist/ build/
