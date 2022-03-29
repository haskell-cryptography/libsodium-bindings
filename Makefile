init: ## Set up git hooks properly - needs calling once
	git config core.hooksPath .githooks

deps: ## Install the dependencies of the backend
	@cabal build --only-dependencies

build: ## Build the project in fast mode
	@cabal build -O0

clean: ## Remove compilation artifacts
	@cabal clean

repl: ## Start a REPL
	@cabal repl --repl-options -fobject-code

lint: ## Run the code linter (HLint)
	@find src -name "*.hs" | parallel -j $(PROCS) -- hlint --refactor-options="-i" --refactor {}

style: ## Run the code formatter (ormolu)
	@find src -name "*.hs" | parallel -j $(PROCS) -- ormolu -m inplace {}
	@cabal-fmt -i *.cabal

help: ## Display this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.* ?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

PROCS := $(shell nproc)

.PHONY: all $(MAKECMDGOALS)

.DEFAULT_GOAL := help
