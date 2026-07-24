#!/bin/bash

# Utility script to removing chaosmesh from the K8S cluster, to clean up test artefacts
# source: https://github.com/canonical/mongo-single-kernel-library/blob/8/edge/tests/integration/helpers/scripts/destroy_chaos_mesh.sh

chaos_mesh_ns=$1

if [ -z "${chaos_mesh_ns}" ]; then
    echo "Usage: $0 <namespace>"
    exit 1
fi

# Chaos Mesh CRs (e.g. NetworkChaos) use finalizers like chaos-mesh/records that only the
# controller removes. If helm is uninstalled first (or the controller is already gone),
# those CRs stay Terminating forever and block namespace / juju model destruction.
remove_finalizers_from_chaos_crs() {
    echo "removing finalizers from chaos-mesh custom resources..."
    for kind in $(sudo k8s kubectl api-resources --verbs=list --namespaced -o name 2>/dev/null | grep -i 'chaos-mesh.org' || true); do
        while read -r ns name; do
            [ -z "${ns}" ] && continue
            echo "  clearing finalizers on ${kind} ${ns}/${name}"
            sudo k8s kubectl patch "${kind}" "${name}" -n "${ns}" \
                -p '{"metadata":{"finalizers":[]}}' --type=merge || :
        done < <(sudo k8s kubectl get "${kind}" --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)
    done
}

delete_chaos_crs() {
    echo "deleting chaos-mesh custom resources..."
    for kind in $(sudo k8s kubectl api-resources --verbs=list --namespaced -o name 2>/dev/null | grep -i 'chaos-mesh.org' || true); do
        timeout 30 sudo k8s kubectl delete "${kind}" --all --all-namespaces || :
    done
}

destroy_chaos_mesh() {
    # 1. Delete CRs while the controller may still be running (preferred path).
    delete_chaos_crs

    # 2. Strip CR finalizers in case the controller never cleaned them up.
    remove_finalizers_from_chaos_crs
    delete_chaos_crs

    # 3. Let Helm attempt a graceful uninstall.
    # (If we delete CRDs/Webhooks first, Helm usually hangs or fails)
    if [ "$(sudo k8s helm list --namespace "${chaos_mesh_ns}" | grep -c 'chaos-mesh')" -ge "1" ]; then
        echo "uninstalling chaos-mesh helm release..."
        sudo k8s helm uninstall chaos-mesh --namespace "${chaos_mesh_ns}" || :
    fi

    # 4. After helm uninstall, controller is gone — strip any leftover CR finalizers again.
    remove_finalizers_from_chaos_crs
    delete_chaos_crs

    # 5. Webhook configurations are cluster-scoped (removing the -n flag)
    echo "deleting mutating and validating webhooks..."
    sudo k8s kubectl get mutatingwebhookconfiguration -o name | grep -i 'chaos-mesh' | xargs -r timeout 30 sudo k8s kubectl delete || :
    sudo k8s kubectl get validatingwebhookconfiguration -o name | grep -i 'chaos-mesh' | xargs -r timeout 30 sudo k8s kubectl delete || :

    # 6. Use xargs to safely pass multiple arguments for deletion
    echo "deleting clusterrolebindings..."
    sudo k8s kubectl get clusterrolebinding -o name | grep -i 'chaos-mesh' | xargs -r timeout 30 sudo k8s kubectl delete || :

    echo "deleting clusterroles..."
    sudo k8s kubectl get clusterrole -o name | grep -i 'chaos-mesh' | xargs -r timeout 30 sudo k8s kubectl delete || :

    echo "removing finalizers from crds to prevent hanging..."
    sudo k8s kubectl get crd -o name | grep -i 'chaos-mesh.org' | xargs -r -I {} sudo k8s kubectl patch {} -p '{"metadata":{"finalizers":[]}}' --type=merge || :

    echo "deleting crds..."
    sudo k8s kubectl get crd -o name | grep -i 'chaos-mesh.org' | xargs -r timeout 30 sudo k8s kubectl delete || :

    # 7. Clean up any leftover hanging resources in the namespace
    echo "cleaning up leftover namespace resources..."
    sudo k8s kubectl delete all -l app.kubernetes.io/instance=chaos-mesh -n "${chaos_mesh_ns}" || :
}

echo "Destroying chaos mesh in ${chaos_mesh_ns}"
destroy_chaos_mesh
echo "Cleanup complete."
