package bypass

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"kmesh.net/kmesh/pkg/bpf"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerField("bypass")

func getCurrentNodeName(client kubernetes.Interface, podName, namespace string) (string, error) {
	pod, err := client.CoreV1().Pods(namespace).Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("error getting pod %s in namespace %s: %v", podName, namespace, err)
	}

	nodeName := pod.Spec.NodeName

	return nodeName, nil
}

func StartPodEventWatcher(client kubernetes.Interface, podName, podNamespace string) error {
	stopChan := make(chan struct{})

	nodeName, err := getCurrentNodeName(client, podName, podNamespace)
	if err != nil {
		log.Error(err)
		return err
	}

	informerFactory := informers.NewSharedInformerFactoryWithOptions(client, 30*time.Second,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.FieldSelector = fmt.Sprintf("spec.nodeName=%s", nodeName)
			options.LabelSelector = "kmesh.net/bypass=enabled"
		}))

	informerFactory.Start(wait.NeverStop)
	informerFactory.WaitForCacheSync(wait.NeverStop)

	podInformer := informerFactory.Core().V1().Pods().Informer()

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				log.Printf("expected *corev1.Pod but got %T", obj)
				return
			}
			log.Printf("%s/%s: MODIFIED", pod.GetNamespace(), pod.GetName())
			podIP := pod.Status.PodIP
			bpf.ObjBypass.KmeshByPassObjects.KmeshByPassMaps.BypassFliterMap.
				Update(podIP, "enabled", ebpf.UpdateAny)
		},
		DeleteFunc: func(obj interface{}) {
			if _, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				return
			}
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				log.Printf("expected *corev1.Pod but got %T", obj)
				return
			}
			log.Printf("%s/%s: DELETED", pod.GetNamespace(), pod.GetName())
			podIP := pod.Status.PodIP
			bpf.ObjBypass.KmeshByPassObjects.KmeshByPassMaps.BypassFliterMap.
				Delete(podIP)
		},
	})

	go podInformer.Run(stopChan)

	return nil
}
