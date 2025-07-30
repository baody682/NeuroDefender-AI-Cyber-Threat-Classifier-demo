FROM python:3.11-slim

RUN apt-get update && apt-get install -y libgomp1

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

CMD ["python", "main.py"]