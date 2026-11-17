.PHONY: test
test:
	@go run -C .make . test

.PHONY: snapshot
snapshot:
	@go run -C .make . snapshot

.PHONY: test-component-identity
test-component-identity:
	@./test/component-identity/run.sh

.PHONY: *
.DEFAULT_GOAL: make-default

make-default:
	@go run -C .make .

.PHONY: *
.DEFAULT:
%:
	@go run -C .make . $@
