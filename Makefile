.PHONY: test lint check-examples clean

test:
	python -m pytest tests/ -v

lint:
	python -m py_compile $$(find src tests -name "*.py")
	python -c "import yaml, glob; [list(yaml.safe_load_all(open(f))) for f in glob.glob('**/*.y*ml', recursive=True) if '.git' not in f]"

check-examples:
	PYTHONPATH=src python -m manifest_guard examples/good.yaml
	PYTHONPATH=src python -m manifest_guard examples/bad.yaml; test $$? -eq 1

clean:
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null; true
	rm -rf .pytest_cache
