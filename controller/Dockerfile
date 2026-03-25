FROM python:3.10-slim

RUN pip install "os-ken>=2.0.0" eventlet requests flask oslo.config

# Make sure pip-installed scripts are on PATH
ENV PATH="/usr/local/bin:${PATH}"

COPY simple_switch_13.py /app/simple_switch_13.py
COPY run_controller.py /app/run_controller.py
COPY block_agent.py /app/block_agent.py
WORKDIR /app

EXPOSE 6633 8080

CMD ["python", "run_controller.py"]
