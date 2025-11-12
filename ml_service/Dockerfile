FROM python:3.11-slim

WORKDIR /app

COPY ml_service/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY ml_service/main.py ml_service/train.py ./

ENV MODEL_PATH=/models/ueba.joblib
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
