FROM python:3.9-slim

# Install OpenSSL and other dependencies
RUN apt-get update && apt-get install -y openssl && apt-get clean

# Set up working directory
WORKDIR /app

# Copy application files
COPY app.py requirements.txt ./
COPY templates ./templates/
COPY static ./static/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create directories for file uploads
RUN mkdir -p uploads results

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

# Expose the web server port
EXPOSE 5000

# Run the web server
CMD ["flask", "run"]