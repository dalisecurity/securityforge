FROM python:3.11-slim

LABEL maintainer="WAF Payload Database"
LABEL description="Containerized WAF testing tool with comprehensive payload database"

# Set working directory
WORKDIR /app

# Copy application files
COPY waf_tester.py /app/
COPY payloads/ /app/payloads/
COPY README.md QUICKSTART.md LICENSE /app/

# Create output directory
RUN mkdir -p /app/reports

# Make script executable
RUN chmod +x waf_tester.py

# Set entrypoint
ENTRYPOINT ["python3", "waf_tester.py"]

# Default to interactive mode
CMD ["-i"]
