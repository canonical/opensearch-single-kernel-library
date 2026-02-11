# opensearch-single-kernel-library
Library including shared code for OpenSearch Charms (K8s, VM)

Kubernetes requires unsafe sysctls to be explicitly allowed at the kubelet level. 
For MicroK8s, add the following to allow net.ipv4.tcp_retries2:

```shell
sudo vi /var/snap/microk8s/current/args/kubelet
#Add following line to file:
# --allowed-unsafe-sysctls=net.ipv4.tcp_retries2
microk8s.stop
microk8s.start
```
For other Kubernetes distributions, configure the kubelet's --allowed-unsafe-sysctls flag accordingly. 
Without this configuration, Kubernetes will reject the pod spec and the charm may fail to deploy.
