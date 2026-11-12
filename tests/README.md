# Website smoke tests

Run only the website tests:

```bash
python -m unittest discover -s tests -p "test_web_*.py"
```

Run the full test suite:

```bash
python -m unittest discover -s tests
```

The website tests use Flask's built-in test client. They render each page, check
that frontend assets are served, and call read-only dashboard APIs without
starting a web server or changing detection settings.
