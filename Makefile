KUBE_CONTEXT := rancher-desktop
KUBECTL := kubectl --context=$(KUBE_CONTEXT)
MAPPER_JAR := mapper/target/oid4vc-mapper-1.0.0-SNAPSHOT.jar

keycloak-setup:
	bin/oid4vci-setup

keycloak-update: $(MAPPER_JAR)
	$(KUBECTL) cp $(MAPPER_JAR) busybox:/providers/
	$(KUBECTL) delete pod keycloak-0 --wait=false
	@echo "Waiting for pod to be recreated..."
	@while ! $(KUBECTL) get pod keycloak-0 >/dev/null 2>&1; do sleep 1; done
	$(KUBECTL) wait pod/keycloak-0 --for=condition=Ready --timeout=60s
