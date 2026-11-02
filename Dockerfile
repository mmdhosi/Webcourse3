FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY proxy.py jwt_auth.py generate_token.py ./
USER 65532:65532
EXPOSE 8000
CMD ["python", "proxy.py"]
