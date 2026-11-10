IMAGE ?= filevet:test
SAMPLES := tmp-samples

.PHONY: lint typecheck test build docker smoke

lint:
	uv run ruff check .
	uv run ruff format --check .

typecheck:
	uv run mypy src/

test:
	uv run pytest -n auto --cov --cov-report=xml --junitxml=junit.xml
	uv run coverage report --include='*/filevet/core/*' --fail-under=90

build:
	uv build

docker:
	docker build -t $(IMAGE) .
	$(MAKE) smoke

smoke:
	mkdir -p $(SAMPLES)
	printf '%%PDF-1.4\n%%%%EOF\n' > $(SAMPLES)/benign.pdf
	docker run --rm --network none -v "$(CURDIR)/$(SAMPLES):/samples:ro" $(IMAGE) scan /samples/benign.pdf > $(SAMPLES)/report.json
	python3 -c 'import json, sys; assert isinstance(json.load(open(sys.argv[1]))["findings"], list)' $(SAMPLES)/report.json
