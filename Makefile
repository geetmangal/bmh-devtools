PY := .venv/bin/python
PIP := .venv/bin/pip
PORT ?= 8765
TAILWIND_VERSION ?= v3.4.17
TAILWIND_SHA256 ?= 7d24f7fa191d2193b78cd5f5a42a6093e14409521908529f42d80b11fde1f1d4
TAILWIND := .cache/tailwindcss-$(TAILWIND_VERSION)

.PHONY: venv run css test test-network docker docker-up docker-down clean

venv: .venv/bin/activate
.venv/bin/activate: requirements.txt
	python3 -m venv .venv
	$(PIP) install -q -r requirements.txt
	touch .venv/bin/activate

$(TAILWIND):
	mkdir -p .cache
	curl -fsSL -o $@.tmp https://github.com/tailwindlabs/tailwindcss/releases/download/$(TAILWIND_VERSION)/tailwindcss-linux-x64
	echo "$(TAILWIND_SHA256)  $@.tmp" | sha256sum -c -
	chmod +x $@.tmp && mv $@.tmp $@

# Minified CSS (the Docker image builds the same file in its css stage).
css: $(TAILWIND)
	$(TAILWIND) -c tailwind.config.js -i assets/tools.css -o app/static/css/tools.css --minify

run: venv css
	.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port $(PORT) --reload

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
	rm -rf .venv .pytest_cache .cache app/static/css/tools.css
	find . -name __pycache__ -type d -exec rm -rf {} +
