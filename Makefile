DOCKER_IMAGE := us-docker.pkg.dev/grafanalabs-dev/docker-application-gateway-kubernetes-ingress-dev/application-gateway-kubernetes-ingress
DOCKER_TAG := $(shell git rev-parse --short HEAD)

.PHONY: test
test:
	go test ./...

.PHONY: build-binary
build-binary: clean-bin
	# Create bin directory
	mkdir -p bin
	
	# Statically link binaries, in order to avoid issues with missing libraries
	# if the binary is built on a distribution with different libraries then the runtime.
	
	# Linux binaries
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-extldflags \"-static\"" -o bin/appgw_ingress_linux_amd64 ./cmd/appgw-ingress
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-extldflags \"-static\"" -o bin/appgw_ingress_linux_arm64 ./cmd/appgw-ingress
	
	# Darwin binaries
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o bin/appgw_ingress_darwin_amd64 ./cmd/appgw-ingress
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o bin/appgw_ingress_darwin_arm64 ./cmd/appgw-ingress

.PHONY: clean-bin
clean-bin:
	# Clean up previous builds
	rm -rf bin/

.PHONY: clean
clean: clean-bin

# Manually build and push multi-arch Docker image.
.PHONY: build-and-push-image
build-and-push-image: build-binary
	docker buildx create --use --name application-gateway-kubernetes-ingress-builder || true
	docker buildx inspect application-gateway-kubernetes-ingress-builder --bootstrap
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--build-arg REVISION=$(DOCKER_TAG) \
		-t $(DOCKER_IMAGE):latest \
		-t $(DOCKER_IMAGE):$(DOCKER_TAG) \
		--push .
