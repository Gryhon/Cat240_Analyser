#!/bin/bash

VENV_NAME="venv_cat240"
FORCE=false
CLEAN=false

for arg in "$@"; do
    if [ "$arg" = "--force" ] || [ "$arg" = "-f" ]; then
        FORCE=true
    fi
    if [ "$arg" = "--clean" ] || [ "$arg" = "-c" ]; then
        CLEAN=true
    fi
done

if [ "$CLEAN" = true ]; then
    echo "Removing virtual environment '$VENV_NAME'..."
    rm -rf "$VENV_NAME"
    echo "Done."
    return 0 2>/dev/null || exit 0
fi

if [ "$FORCE" = true ]; then
    echo "Force mode: removing existing virtual environment..."
    rm -rf "$VENV_NAME"
fi

# pyenv initialisieren (falls installiert aber nicht im PATH)
if ! command -v pyenv &> /dev/null; then
    export PYENV_ROOT="$HOME/.pyenv"
    export PATH="$PYENV_ROOT/bin:$PATH"
fi
if command -v pyenv &> /dev/null; then
    eval "$(pyenv init -)"
fi

if [ -f .python-version ]; then
    PY_VERSION=$(cat .python-version)

    if ! command -v pyenv &> /dev/null; then
        echo "Warning: pyenv not found. Using system Python (may differ from $PY_VERSION)."
    else
        # Prüfe, ob die Version bereits installiert ist
        if pyenv versions --bare | grep -qx "$PY_VERSION"; then
            echo "Python $PY_VERSION is already installed."
        else
            echo "Installing Python $PY_VERSION..."
            pyenv install "$PY_VERSION"
        fi
        pyenv local "$PY_VERSION"
    fi
else
    echo "No .python-version file found, skipping pyenv."
fi

# Python-Binary ermitteln (pyenv shim bevorzugen)
PYTHON_BIN=$(command -v python3)

# Check if Python3 and venv are installed
if ! "$PYTHON_BIN" -m venv --help &> /dev/null; then
    echo "Python3 or the venv module is not installed."
    return 1 2>/dev/null || exit 1
fi

# Create the virtual environment
if [ ! -d "$VENV_NAME" ]; then
    "$PYTHON_BIN" -m venv "$VENV_NAME"
    echo "Virtual environment '$VENV_NAME' has been created."
else
    echo "Virtual environment '$VENV_NAME' already exists, skipping creation. Use --force to recreate."
fi

# Activate the virtual environment
echo "Activating the virtual environment..."
source "./$VENV_NAME/bin/activate"

# Confirm that the environment is activated
if [[ "$VIRTUAL_ENV" != "" ]]; then
    echo "The virtual environment '$VENV_NAME' is now activated."

    # Check if requirements.txt exists and install packages
    if [ -f "requirements.txt" ]; then
        echo "Installing required packages from requirements.txt..."
        pip install --upgrade pip
        pip install pytest
        pip install -r requirements.txt
        echo "Packages installed successfully."
    else
        echo "No requirements.txt file found. Skipping package installation."
    fi
else
    echo "Error activating the virtual environment."
fi

python3 --version

