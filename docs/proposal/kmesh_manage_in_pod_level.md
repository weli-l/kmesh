## Add feature of kmesh management at pod level

### How to enable kmesh management at pod level

```shell
kubectl label pod xxx istio.io/dataplane-mode=Kmesh
```

### How to judge whether pod is managed by Kmesh

Due to the feature of the bypass, the impact of the bypass needs to be considered comprehensively

- Label priority（From high to low）
  - kmesh.net/bypass=enabled
  - istio.io/dataplane-mode=Kmesh(pod)
  - istio.io/dataplane-mode=Kmesh(namespace)

- Annotation priority（From high to low，and it is only be used for user to judge whether pod is managed by kmesh）
  - kmesh.net/bypass=enabled
  - kmesh.net/redirection=enabled(pod)
  - kmesh.net/redirection=enabled(namespace)

### How to watch label

The Kmesh Daemon observes changes in the Kubernetes API Server and implements observation of specific labels using a Field Selector. It communicates with the kube-apiserver, filters the desired resource objects, and thus only observes changes specific to certain labels.

```go
informerFactory := informers.NewSharedInformerFactoryWithOptions(client, DefaultInformerSyncPeriod,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.FieldSelector = fmt.Sprintf("spec.nodeName=%s", nodeName)
      options.LabelSelector = LabelSelectorKmesh//label:istio.io/dataplane-mode=Kmesh
		}))
```

### How does kmesh daemon process and manage pods

When the informer observes that a pod is labeled, it sends a socket to port 929 of 0.0.0.1 and records the cookie information of the current pod in bpfmap.