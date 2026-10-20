KUBE_CONTEXT := rancher-desktop
KUBECTL := kubectl --context=$(KUBE_CONTEXT)
KEYCLOAK_DIR ?= ../keycloak
KEYCLOAK_HOME_DIR ?= $(KEYCLOAK_DIR)/quarkus/dist/target/keycloak-999.0.0-SNAPSHOT
KEYCLOAK_FEATURES ?= "oid4vc-vci,oid4vc-vci-preauth-code"

build:
	mvn clean package -DskipTests

images: build
	docker build -t nessus/oid4vc-demo-ticket:1.0.0-SNAPSHOT demo/airport/ticket
	docker build -t nessus/oid4vc-demo-checkin:1.0.0-SNAPSHOT demo/airport/checkin
	docker build -t nessus/oid4vc-demo-gate:1.0.0-SNAPSHOT demo/airport/gate

keycloak-build:
	@cd $(KEYCLOAK_DIR) && ./mvnw -pl 'quarkus/dist,!crypto/fips1402,tests,testsuite/integration-arquillian/tests/base' -am -DskipTests clean install
	@tar xzf $(KEYCLOAK_DIR)/quarkus/dist/target/keycloak-999.0.0-SNAPSHOT.tar.gz -C $(KEYCLOAK_DIR)/quarkus/dist/target

keycloak-login:
	@$(eval KC_ADMIN_PASSWORD := $(shell $(KUBECTL) get secret keycloak-secret -o jsonpath='{.data.ADMIN_PASSWORD}' | base64 -d))
	@bin/oid4vc login --server http://localhost:30800 --password "$(KC_ADMIN_PASSWORD)"

keycloak-image: keycloak-build
	@cd $(KEYCLOAK_DIR)/quarkus/container && cp ../dist/target/keycloak-999.0.0-SNAPSHOT.tar.gz . && \
		docker buildx build --platform linux/amd64 --build-arg KEYCLOAK_DIST=keycloak-999.0.0-SNAPSHOT.tar.gz -t keycloak:latest .

keycloak-setup:
	scripts/oid4vc-setup

keycloak-tests:
	@cd $(KEYCLOAK_DIR) && \
		mvn -pl services clean test -Dtest='org.keycloak.protocol.oid4vc.**' && \
		mvn -pl tests/base clean test -Dtest='org.keycloak.tests.oid4vc.**'

upgrade: images
	helm upgrade --kube-context=$(KUBE_CONTEXT) --install nessus-services ./helm -f ./helm/values-services-dev.yaml
