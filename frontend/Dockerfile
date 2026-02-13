FROM python:3.9-slim

WORKDIR /app

RUN pip install streamlit pandas requests plotly

COPY . .

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0"]
