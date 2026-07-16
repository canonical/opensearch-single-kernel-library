#!/bin/bash

# Utility script to removing chaosmesh from the K8S cluster, to clean up test artefacts
# source: https://github.com/canonical/mongo-single-kernel-library/blob/8/edge/tests/integration/helpers/scripts/destroy_chaos_mesh.sh

chaos_mesh_ns=$1

if [ -z "${chaos_mesh_ns}" ]; then
    echo "Usage: $0 <namespace>"
    exit 1
fi

destroy_chaos_mesh() {
    # 1. Let Helm attempt a graceful uninstall first.
    # (If we delete CRDs/Webhooks first, Helm usually hangs or fails)
    if [ "$(sudo k8s helm list --namespace "${chaos_mesh_ns}" | grep -c 'chaos-mesh')" -ge "1" ]; then
        echo "uninstalling chaos-mesh helm release..."
        sudo k8s helm uninstall chaos-mesh --namespace "${chaos_mesh_ns}" || :
    fi

    # 2. Delete custom chaos resources
    echo "deleting api-resources..."
    for i in $(sudo k8s kubectl api-resources | grep -i 'chaos-mesh' | awk '{print $1}'); do
        timeout 30 sudo k8s kubectl delete "${i}" --all --all-namespaces || :
    done

    # 3. Webhook configurations are cluster-scoped (removing the -n flag)
    echo "deleting mutating and validating webhooks..."
    sudo k8s kubectl get mutatingwebhookconfiguration -o name | grep -i 'chaos-mesh' | xargs -r timeout 30 sudo k8s kubectl delete || :
    sudo k8s kubectl get validatingwebhookconfiguration -o name | grep -i 'chaos-mesh' | xargs -r timeout 30 sudo k8s kubectl delete || :

    # 4. Use xargs to safely pass multiple arguments for deletion
    echo "deleting clusterrolebindings..."
    sudo k8s kubectl get clusterrolebinding -o name | grep -i 'chaos-mesh' | xargs -r timeout 30 sudo k8s kubectl delete || :

    echo "deleting clusterroles..."
    sudo k8s kubectl get clusterrole -o name | grep -i 'chaos-mesh' | xargs -r timeout 30 sudo k8s kubectl delete || :

    echo "removing finalizers from crds to prevent hanging..."
    sudo k8s kubectl get crd -o name | grep -i 'chaos-mesh.org' | xargs -r -I {} sudo k8s kubectl patch {} -p '{"metadata":{"finalizers":[]}}' --type=merge || :

    echo "deleting crds..."
    sudo k8s kubectl get crd -o name | grep -i 'chaos-mesh.org' | xargs -r timeout 30 sudo k8s kubectl delete || :

    # 5. Clean up any leftover hanging resources in the namespace
    echo "cleaning up leftover namespace resources..."
    sudo k8s kubectl delete all -l app.kubernetes.io/instance=chaos-mesh -n "${chaos_mesh_ns}" || :
}

echo "Destroying chaos mesh in ${chaos_mesh_ns}"
destroy_chaos_mesh
echo "Cleanup complete."
