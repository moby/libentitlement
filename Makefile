# run all lint functionality - excludes vendoring
lint:
	@echo "+ $@: gofmt, golint, govet, gocyclo, misspell, ineffassign"
	# gofmt
	@test -z "$$(gofmt -s -l .| grep -v .pb. | grep -v vendor/ | tee /dev/stderr)"
	# golint
	@test -z "$(shell find . -type f -name "*.go" -not -path "./vendor/*" -not -name "*.pb.*" -exec golint {} \; | tee /dev/stderr)"
	# govet
	@test -z "$$(go tool vet -printf=false . 2>&1 | grep -v vendor/ | tee /dev/stderr)"
	# gocyclo - we require cyclomatic complexity to be < 16
	@test -z "$(sh find . -type f -name "*.go" -not -path "./vendor/*" -not -name "*.pb.*" -exec gocyclo -over 15 {} \; | tee /dev/stderr)"
	# misspell - requires that the following be run first:
	#    go get -u github.com/client9/misspell/cmd/misspell
	@test -z "$$(find . -type f | grep -v vendor/ | grep -v bin/ | grep -v misc/ | grep -v .git/ | grep -v \.pdf | xargs misspell | tee /dev/stderr)"
	# ineffassign - requires that the following be run first:
	#    go get -u github.com/gordonklaus/ineffassign
	@test -z "$(sh find . -type f -name "*.go" -not -path "./vendor/*" -not -name "*.pb.*" -exec ineffassign {} \; | tee /dev/stderr)"


test: lint
	go test .
