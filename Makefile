KUBE_CONTEXT := rancher-desktop
KUBECTL := kubectl --context=$(KUBE_CONTEXT)
MAPPER_JAR := mapper/target/oid4vc-mapper-1.0.0-SNAPSHOT.jar

build:
	mvn clean package -DskipTests

images: build
	docker build -t nessus/oid4vc-demo-ticket:1.0.0-SNAPSHOT demo/airport/ticket
	docker build -t nessus/oid4vc-demo-checkin:1.0.0-SNAPSHOT demo/airport/checkin

keycloak-login:
	$(eval KC_ADMIN_PASSWORD := $(shell $(KUBECTL) get secret keycloak-secret -o jsonpath='{.data.ADMIN_PASSWORD}' | base64 -d))
	bin/oid4vc login --server http://localhost:30800 --password "$(KC_ADMIN_PASSWORD)"

keycloak-setup:
	bin/oid4vci-setup

keycloak-mapper-update: $(MAPPER_JAR)
	$(KUBECTL) cp $(MAPPER_JAR) busybox:/providers/
	$(KUBECTL) rollout restart statefulset keycloak
	$(KUBECTL) rollout status statefulset keycloak --timeout=60s

upgrade: images
	helm upgrade --kube-context=$(KUBE_CONTEXT) --install nessus-services ./helm -f ./helm/values-services-dev.yaml
