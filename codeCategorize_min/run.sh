#!/bin/bash
# Run both FastAPI server and Streamlit app

echo "Starting File Language Detector..."
echo "=================================="
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Creating one..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies if needed
if ! python -c "import fastapi" 2>/dev/null; then
    echo "Installing dependencies..."
    pip install -r requirements.txt
fi

# Create temp directory
mkdir -p temp

# Start FastAPI server in background
echo "Starting FastAPI server on http://localhost:8000..."
python server.py &
SERVER_PID=$!

# Wait for server to start
sleep 3

# Start Streamlit
echo "Starting Streamlit app..."
echo ""
echo "=================================="
echo "Access the web interface in your browser"
echo "Press Ctrl+C to stop both servers"
echo "=================================="
echo ""

streamlit run app.py

# Clean up: kill server when Streamlit exits
kill $SERVER_PID 2>/dev/null
echo ""
echo "Servers stopped."
