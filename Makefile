PY := .venv/bin/python
PIP := .venv/bin/pip
PORT ?= 8765

.PHONY: venv run test test-network docker docker-up docker-down clean

venv: .venv/bin/activate
.venv/bin/activate: requirements.txt
	python3 -m venv .venv
	$(PIP) install -q -r requirements.txt
	touch .venv/bin/activate

run: venv
	.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port $(PORT) --reload --proxy-headers

test: venv
	$(PY) -m pytest -q -m "not network"

test-network: venv
	$(PY) -m pytest -q -m network

docker:
	docker build -t bmh-devtools:latest .

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

clean:
	rm -rf .venv .pytest_cache
	find . -name __pycache__ -type d -exec rm -rf {} +
