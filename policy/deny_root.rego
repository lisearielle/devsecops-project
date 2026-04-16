package main

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.runAsUser == 0
  msg := sprintf("ERREUR: Le conteneur '%v' tourne en tant que root (runAsUser=0). Interdit !", [container.name])
}
