# CNI

## Cilium

LEARNING
- we could filter hubble logs with
  - `is_reply=false`, we don't build network policies on answers
  - the identity should be known or world, probably we are not interested in traffic to localhost

MONITOR
- [LIMIT] here we miss the monitor mode -> we can use learning, we should contribute upstream [UPSTREAM]

PROTECT
- [LIMIT] we cannot compute the policy associated to the drop -> we can use some code in our controller

## Calico

[LIMIT] in caso di traffico da/verso esterno non mostra gli IP ma solo `pub/pvt` -> we should contribute upstream

LEARNING
- we could filter goldmane logs with
  - calico non manda la reply, semplicemente aggrega il flow e lo fa vedere sia a sorgente sia a destinazione

MONITOR
- we have the staged policy

PROTECT
- we can use the normal k8s policy
