.DEFAULT_GOAL := test
LISP ?= sbcl

test:
	./scripts/run-tests.sh

.PHONY: test
