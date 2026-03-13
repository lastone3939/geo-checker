#!/bin/sh
exec gunicorn app:app --bind "0.0.0.0:${PORT:-8080}" --workers 1 --timeout 180 --keep-alive 5
