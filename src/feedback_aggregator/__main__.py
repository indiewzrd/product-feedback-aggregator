"""Allow ``python -m feedback_aggregator`` to run the CLI."""

from .cli import main

raise SystemExit(main())
