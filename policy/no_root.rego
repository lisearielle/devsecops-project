package main

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.runAsNonRoot
  msg := sprintf("ERREUR : Le conteneur '%v' tourne en root. Ajoutez securityContext.runAsNonRoot: true", [container.name])
}
