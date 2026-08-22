package collectors

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/sametsenturka/kubehunt/internal/domain"
)

const (
	defaultPageSize    = int64(500)
	defaultConcurrency = 4
)

type Scope struct {
	Namespaces []string
}

type Collector interface {
	Collect(context.Context, kubernetes.Interface, domain.ClusterMetadata, Scope) (domain.ClusterState, error)
}

type ClusterCollector struct {
	PageSize    int64
	Concurrency int
}

func NewClusterCollector() *ClusterCollector {
	return &ClusterCollector{PageSize: defaultPageSize, Concurrency: defaultConcurrency}
}

func (collector *ClusterCollector) Collect(ctx context.Context, client kubernetes.Interface, cluster domain.ClusterMetadata, scope Scope) (domain.ClusterState, error) {
	if client == nil {
		return domain.ClusterState{}, fmt.Errorf("collect cluster inventory: Kubernetes client is nil")
	}
	namespaces, err := normalizeScope(scope.Namespaces)
	if err != nil {
		return domain.ClusterState{}, fmt.Errorf("collect cluster inventory: %w", err)
	}

	cluster.NamespaceScope = append([]string(nil), namespaces...)
	state := domain.ClusterState{Cluster: cluster, Collections: make(map[domain.ResourceKind]domain.CollectionMetadata)}
	pageSize := collector.PageSize
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}

	tasks := []collectionTask{
		collector.namespaceTask(client, namespaces, &state),
		collector.podTask(client, namespaces, pageSize, &state),
		collector.deploymentTask(client, namespaces, pageSize, &state),
		collector.statefulSetTask(client, namespaces, pageSize, &state),
		collector.daemonSetTask(client, namespaces, pageSize, &state),
		collector.serviceTask(client, namespaces, pageSize, &state),
		collector.ingressTask(client, namespaces, pageSize, &state),
		collector.serviceAccountTask(client, namespaces, pageSize, &state),
		collector.roleTask(client, namespaces, pageSize, &state),
		collector.clusterRoleTask(client, pageSize, &state),
		collector.roleBindingTask(client, namespaces, pageSize, &state),
		collector.clusterRoleBindingTask(client, pageSize, &state),
		collector.networkPolicyTask(client, namespaces, pageSize, &state),
		collector.validatingAdmissionPolicyTask(client, pageSize, &state),
		collector.validatingAdmissionPolicyBindingTask(client, pageSize, &state),
		collector.validatingWebhookConfigurationTask(client, pageSize, &state),
	}

	concurrency := collector.Concurrency
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}
	results := runCollectionTasks(ctx, tasks, concurrency)
	var collectionErrors []error
	for index, result := range results {
		if result.err != nil {
			if tasks[index].optionalAPI && apierrors.IsNotFound(result.err) {
				continue
			}
			collectionErrors = append(collectionErrors, fmt.Errorf("collect %s: %w", tasks[index].kind, result.err))
			continue
		}
		state.Collections[tasks[index].kind] = domain.CollectionMetadata{
			ResourceVersion: result.resourceVersion,
			StartedAt:       result.startedAt,
			EndedAt:         result.endedAt,
			Count:           state.Count(tasks[index].kind),
		}
	}
	if len(collectionErrors) > 0 {
		return state, fmt.Errorf("cluster inventory is incomplete: %w", errors.Join(collectionErrors...))
	}

	sortState(&state)
	return state, nil
}

type collectionTask struct {
	kind        domain.ResourceKind
	optionalAPI bool
	run         func(context.Context) (string, error)
}

type collectionTaskResult struct {
	resourceVersion string
	startedAt       time.Time
	endedAt         time.Time
	err             error
}

func runCollectionTasks(ctx context.Context, tasks []collectionTask, concurrency int) []collectionTaskResult {
	results := make([]collectionTaskResult, len(tasks))
	semaphore := make(chan struct{}, concurrency)
	var waitGroup sync.WaitGroup
	for index := range tasks {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				results[index] = collectionTaskResult{startedAt: time.Now().UTC(), endedAt: time.Now().UTC(), err: ctx.Err()}
				return
			}

			startedAt := time.Now().UTC()
			resourceVersion, err := tasks[index].run(ctx)
			results[index] = collectionTaskResult{
				resourceVersion: resourceVersion,
				startedAt:       startedAt,
				endedAt:         time.Now().UTC(),
				err:             err,
			}
		}(index)
	}
	waitGroup.Wait()
	return results
}

type pageFetcher[T any] func(context.Context, metav1.ListOptions) ([]T, string, string, error)

func listAll[T any](ctx context.Context, pageSize int64, fetch pageFetcher[T]) ([]T, string, error) {
	var result []T
	continueToken := ""
	resourceVersion := ""
	for {
		items, pageResourceVersion, nextToken, err := fetch(ctx, metav1.ListOptions{Limit: pageSize, Continue: continueToken})
		if err != nil {
			return nil, "", err
		}
		if resourceVersion == "" {
			resourceVersion = pageResourceVersion
		}
		result = append(result, items...)
		if nextToken == "" {
			return result, resourceVersion, nil
		}
		continueToken = nextToken
	}
}

func listNamespaced[T any](ctx context.Context, namespaces []string, pageSize int64, fetch func(string) pageFetcher[T]) ([]T, string, error) {
	if len(namespaces) == 0 {
		return listAll(ctx, pageSize, fetch(metav1.NamespaceAll))
	}
	var result []T
	resourceVersion := ""
	for _, namespace := range namespaces {
		items, version, err := listAll(ctx, pageSize, fetch(namespace))
		if err != nil {
			return nil, "", fmt.Errorf("namespace %q: %w", namespace, err)
		}
		result = append(result, items...)
		if len(namespaces) == 1 {
			resourceVersion = version
		}
	}
	return result, resourceVersion, nil
}

func (collector *ClusterCollector) namespaceTask(client kubernetes.Interface, namespaces []string, state *domain.ClusterState) collectionTask {
	return collectionTask{kind: domain.KindNamespaces, run: func(ctx context.Context) (string, error) {
		var items []corev1.Namespace
		resourceVersion := ""
		if len(namespaces) == 0 {
			listed, version, err := listAll(ctx, collector.pageSize(), func(ctx context.Context, options metav1.ListOptions) ([]corev1.Namespace, string, string, error) {
				page, err := client.CoreV1().Namespaces().List(ctx, options)
				if err != nil {
					return nil, "", "", err
				}
				return page.Items, page.ResourceVersion, page.Continue, nil
			})
			if err != nil {
				return "", err
			}
			items, resourceVersion = listed, version
		} else {
			for _, namespace := range namespaces {
				item, err := client.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
				if err != nil {
					return "", fmt.Errorf("namespace %q: %w", namespace, err)
				}
				items = append(items, *item)
			}
			if len(items) == 1 {
				resourceVersion = items[0].ResourceVersion
			}
		}
		state.Namespaces = mapItems(items, normalizeNamespace)
		return resourceVersion, nil
	}}
}

func (collector *ClusterCollector) podTask(client kubernetes.Interface, namespaces []string, pageSize int64, state *domain.ClusterState) collectionTask {
	return collectionTask{kind: domain.KindPods, run: func(ctx context.Context) (string, error) {
		items, version, err := listNamespaced(ctx, namespaces, pageSize, func(namespace string) pageFetcher[corev1.Pod] {
			return func(ctx context.Context, options metav1.ListOptions) ([]corev1.Pod, string, string, error) {
				page, err := client.CoreV1().Pods(namespace).List(ctx, options)
				if err != nil {
					return nil, "", "", err
				}
				return page.Items, page.ResourceVersion, page.Continue, nil
			}
		})
		if err != nil {
			return "", err
		}
		state.Pods = mapItems(items, normalizePod)
		return version, nil
	}}
}

func (collector *ClusterCollector) deploymentTask(client kubernetes.Interface, namespaces []string, pageSize int64, state *domain.ClusterState) collectionTask {
	return collectionTask{kind: domain.KindDeployments, run: func(ctx context.Context) (string, error) {
		items, version, err := listNamespaced(ctx, namespaces, pageSize, func(namespace string) pageFetcher[appsv1.Deployment] {
			return func(ctx context.Context, options metav1.ListOptions) ([]appsv1.Deployment, string, string, error) {
				page, err := client.AppsV1().Deployments(namespace).List(ctx, options)
				if err != nil {
					return nil, "", "", err
				}
				return page.Items, page.ResourceVersion, page.Continue, nil
			}
		})
		if err != nil {
			return "", err
		}
		state.Deployments = mapItems(items, normalizeDeployment)
		return version, nil
	}}
}

func (collector *ClusterCollector) statefulSetTask(client kubernetes.Interface, namespaces []string, pageSize int64, state *domain.ClusterState) collectionTask {
	return collectionTask{kind: domain.KindStatefulSets, run: func(ctx context.Context) (string, error) {
		items, version, err := listNamespaced(ctx, namespaces, pageSize, func(namespace string) pageFetcher[appsv1.StatefulSet] {
			return func(ctx context.Context, options metav1.ListOptions) ([]appsv1.StatefulSet, string, string, error) {
				page, err := client.AppsV1().StatefulSets(namespace).List(ctx, options)
				if err != nil {
					return nil, "", "", err
				}
				return page.Items, page.ResourceVersion, page.Continue, nil
			}
		})
		if err != nil {
			return "", err
		}
		state.StatefulSets = mapItems(items, normalizeStatefulSet)
		return version, nil
	}}
}

func (collector *ClusterCollector) daemonSetTask(client kubernetes.Interface, namespaces []string, pageSize int64, state *domain.ClusterState) collectionTask {
	return collectionTask{kind: domain.KindDaemonSets, run: func(ctx context.Context) (string, error) {
		items, version, err := listNamespaced(ctx, namespaces, pageSize, func(namespace string) pageFetcher[appsv1.DaemonSet] {
			return func(ctx context.Context, options metav1.ListOptions) ([]appsv1.DaemonSet, string, string, error) {
				page, err := client.AppsV1().DaemonSets(namespace).List(ctx, options)
				if err != nil {
					return nil, "", "", err
				}
				return page.Items, page.ResourceVersion, page.Continue, nil
			}
		})
		if err != nil {
			return "", err
		}
		state.DaemonSets = mapItems(items, normalizeDaemonSet)
		return version, nil
	}}
}

func (collector *ClusterCollector) serviceTask(client kubernetes.Interface, namespaces []string, pageSize int64, state *domain.ClusterState) collectionTask {
	return collectionTask{kind: domain.KindServices, run: func(ctx context.Context) (string, error) {
		items, version, err := listNamespaced(ctx, namespaces, pageSize, func(namespace string) pageFetcher[corev1.Service] {
			return func(ctx context.Context, options metav1.ListOptions) ([]corev1.Service, string, string, error) {
				page, err := client.CoreV1().Services(namespace).List(ctx, options)
				if err != nil {
					return nil, "", "", err
				}
				return page.Items, page.ResourceVersion, page.Continue, nil
			}
		})
		if err != nil {
			return "", err
		}
		state.Services = mapItems(items, normalizeService)
		return version, nil
	}}
}

func (collector *ClusterCollector) ingressTask(client kubernetes.Interface, namespaces []string, pageSize int64, state *domain.ClusterState) collectionTask {
	return collectionTask{kind: domain.KindIngresses, run: func(ctx context.Context) (string, error) {
		items, version, err := listNamespaced(ctx, namespaces, pageSize, func(namespace string) pageFetcher[networkingv1.Ingress] {
			return func(ctx context.Context, options metav1.ListOptions) ([]networkingv1.Ingress, string, string, error) {
				page, err := client.NetworkingV1().Ingresses(namespace).List(ctx, options)
				if err != nil {
					return nil, "", "", err
				}
				return page.Items, page.ResourceVersion, page.Continue, nil
			}
		})
		if err != nil {
			return "", err
		}
		state.Ingresses = mapItems(items, normalizeIngress)
		return version, nil
	}}
}

func (collector *ClusterCollector) serviceAccountTask(client kubernetes.Interface, namespaces []string, pageSize int64, state *domain.ClusterState) collectionTask {
	return collectionTask{kind: domain.KindServiceAccounts, run: func(ctx context.Context) (string, error) {
		items, version, err := listNamespaced(ctx, namespaces, pageSize, func(namespace string) pageFetcher[corev1.ServiceAccount] {
			return func(ctx context.Context, options metav1.ListOptions) ([]corev1.ServiceAccount, string, string, error) {
				page, err := client.CoreV1().ServiceAccounts(namespace).List(ctx, options)
				if err != nil {
					return nil, "", "", err
				}
				return page.Items, page.ResourceVersion, page.Continue, nil
			}
		})
		if err != nil {
			return "", err
		}
		state.ServiceAccounts = mapItems(items, normalizeServiceAccount)
		return version, nil
	}}
}

func (collector *ClusterCollector) roleTask(client kubernetes.Interface, namespaces []string, pageSize int64, state *domain.ClusterState) collectionTask {
	return collectionTask{kind: domain.KindRoles, run: func(ctx context.Context) (string, error) {
		items, version, err := listNamespaced(ctx, namespaces, pageSize, func(namespace string) pageFetcher[rbacv1.Role] {
			return func(ctx context.Context, options metav1.ListOptions) ([]rbacv1.Role, string, string, error) {
				page, err := client.RbacV1().Roles(namespace).List(ctx, options)
				if err != nil {
					return nil, "", "", err
				}
				return page.Items, page.ResourceVersion, page.Continue, nil
			}
		})
		if err != nil {
			return "", err
		}
		state.Roles = mapItems(items, normalizeRole)
		return version, nil
	}}
}

func (collector *ClusterCollector) clusterRoleTask(client kubernetes.Interface, pageSize int64, state *domain.ClusterState) collectionTask {
	return collectionTask{kind: domain.KindClusterRoles, run: func(ctx context.Context) (string, error) {
		items, version, err := listAll(ctx, pageSize, func(ctx context.Context, options metav1.ListOptions) ([]rbacv1.ClusterRole, string, string, error) {
			page, err := client.RbacV1().ClusterRoles().List(ctx, options)
			if err != nil {
				return nil, "", "", err
			}
			return page.Items, page.ResourceVersion, page.Continue, nil
		})
		if err != nil {
			return "", err
		}
		state.ClusterRoles = mapItems(items, normalizeClusterRole)
		return version, nil
	}}
}

func (collector *ClusterCollector) roleBindingTask(client kubernetes.Interface, namespaces []string, pageSize int64, state *domain.ClusterState) collectionTask {
	return collectionTask{kind: domain.KindRoleBindings, run: func(ctx context.Context) (string, error) {
		items, version, err := listNamespaced(ctx, namespaces, pageSize, func(namespace string) pageFetcher[rbacv1.RoleBinding] {
			return func(ctx context.Context, options metav1.ListOptions) ([]rbacv1.RoleBinding, string, string, error) {
				page, err := client.RbacV1().RoleBindings(namespace).List(ctx, options)
				if err != nil {
					return nil, "", "", err
				}
				return page.Items, page.ResourceVersion, page.Continue, nil
			}
		})
		if err != nil {
			return "", err
		}
		state.RoleBindings = mapItems(items, normalizeRoleBinding)
		return version, nil
	}}
}

func (collector *ClusterCollector) clusterRoleBindingTask(client kubernetes.Interface, pageSize int64, state *domain.ClusterState) collectionTask {
	return collectionTask{kind: domain.KindClusterRoleBindings, run: func(ctx context.Context) (string, error) {
		items, version, err := listAll(ctx, pageSize, func(ctx context.Context, options metav1.ListOptions) ([]rbacv1.ClusterRoleBinding, string, string, error) {
			page, err := client.RbacV1().ClusterRoleBindings().List(ctx, options)
			if err != nil {
				return nil, "", "", err
			}
			return page.Items, page.ResourceVersion, page.Continue, nil
		})
		if err != nil {
			return "", err
		}
		state.ClusterRoleBindings = mapItems(items, normalizeClusterRoleBinding)
		return version, nil
	}}
}

func (collector *ClusterCollector) networkPolicyTask(client kubernetes.Interface, namespaces []string, pageSize int64, state *domain.ClusterState) collectionTask {
	return collectionTask{kind: domain.KindNetworkPolicies, run: func(ctx context.Context) (string, error) {
		items, version, err := listNamespaced(ctx, namespaces, pageSize, func(namespace string) pageFetcher[networkingv1.NetworkPolicy] {
			return func(ctx context.Context, options metav1.ListOptions) ([]networkingv1.NetworkPolicy, string, string, error) {
				page, err := client.NetworkingV1().NetworkPolicies(namespace).List(ctx, options)
				if err != nil {
					return nil, "", "", err
				}
				return page.Items, page.ResourceVersion, page.Continue, nil
			}
		})
		if err != nil {
			return "", err
		}
		state.NetworkPolicies = mapItems(items, normalizeNetworkPolicy)
		return version, nil
	}}
}

func (collector *ClusterCollector) validatingAdmissionPolicyTask(client kubernetes.Interface, pageSize int64, state *domain.ClusterState) collectionTask {
	return collectionTask{kind: domain.KindValidatingAdmissionPolicies, optionalAPI: true, run: func(ctx context.Context) (string, error) {
		items, version, err := listAll(ctx, pageSize, func(ctx context.Context, options metav1.ListOptions) ([]admissionv1.ValidatingAdmissionPolicy, string, string, error) {
			page, err := client.AdmissionregistrationV1().ValidatingAdmissionPolicies().List(ctx, options)
			if err != nil {
				return nil, "", "", err
			}
			return page.Items, page.ResourceVersion, page.Continue, nil
		})
		if err != nil {
			return "", err
		}
		state.ValidatingAdmissionPolicies = mapItems(items, normalizeValidatingAdmissionPolicy)
		return version, nil
	}}
}

func (collector *ClusterCollector) validatingAdmissionPolicyBindingTask(client kubernetes.Interface, pageSize int64, state *domain.ClusterState) collectionTask {
	return collectionTask{kind: domain.KindValidatingAdmissionPolicyBindings, optionalAPI: true, run: func(ctx context.Context) (string, error) {
		items, version, err := listAll(ctx, pageSize, func(ctx context.Context, options metav1.ListOptions) ([]admissionv1.ValidatingAdmissionPolicyBinding, string, string, error) {
			page, err := client.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().List(ctx, options)
			if err != nil {
				return nil, "", "", err
			}
			return page.Items, page.ResourceVersion, page.Continue, nil
		})
		if err != nil {
			return "", err
		}
		state.ValidatingAdmissionPolicyBindings = mapItems(items, normalizeValidatingAdmissionPolicyBinding)
		return version, nil
	}}
}

func (collector *ClusterCollector) validatingWebhookConfigurationTask(client kubernetes.Interface, pageSize int64, state *domain.ClusterState) collectionTask {
	return collectionTask{kind: domain.KindValidatingWebhookConfigurations, run: func(ctx context.Context) (string, error) {
		items, version, err := listAll(ctx, pageSize, func(ctx context.Context, options metav1.ListOptions) ([]admissionv1.ValidatingWebhookConfiguration, string, string, error) {
			page, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, options)
			if err != nil {
				return nil, "", "", err
			}
			return page.Items, page.ResourceVersion, page.Continue, nil
		})
		if err != nil {
			return "", err
		}
		state.ValidatingWebhookConfigurations = mapItems(items, normalizeValidatingWebhookConfiguration)
		return version, nil
	}}
}

func (collector *ClusterCollector) pageSize() int64 {
	if collector.PageSize <= 0 {
		return defaultPageSize
	}
	return collector.PageSize
}

func normalizeScope(namespaces []string) ([]string, error) {
	seen := make(map[string]struct{}, len(namespaces))
	result := make([]string, 0, len(namespaces))
	for _, namespace := range namespaces {
		namespace = strings.TrimSpace(namespace)
		if namespace == "" {
			return nil, fmt.Errorf("namespace filter cannot be empty")
		}
		if _, exists := seen[namespace]; exists {
			continue
		}
		seen[namespace] = struct{}{}
		result = append(result, namespace)
	}
	sort.Strings(result)
	return result, nil
}

func mapItems[Source any, Target any](items []Source, normalize func(Source) Target) []Target {
	result := make([]Target, 0, len(items))
	for _, item := range items {
		result = append(result, normalize(item))
	}
	return result
}

func sortState(state *domain.ClusterState) {
	sortByMetadata(state.Namespaces, func(item domain.Namespace) domain.Metadata { return item.Metadata })
	sortByMetadata(state.Pods, func(item domain.Pod) domain.Metadata { return item.Metadata })
	sortByMetadata(state.Deployments, func(item domain.Workload) domain.Metadata { return item.Metadata })
	sortByMetadata(state.StatefulSets, func(item domain.Workload) domain.Metadata { return item.Metadata })
	sortByMetadata(state.DaemonSets, func(item domain.Workload) domain.Metadata { return item.Metadata })
	sortByMetadata(state.Services, func(item domain.Service) domain.Metadata { return item.Metadata })
	sortByMetadata(state.Ingresses, func(item domain.Ingress) domain.Metadata { return item.Metadata })
	sortByMetadata(state.ServiceAccounts, func(item domain.ServiceAccount) domain.Metadata { return item.Metadata })
	sortByMetadata(state.Roles, func(item domain.Role) domain.Metadata { return item.Metadata })
	sortByMetadata(state.ClusterRoles, func(item domain.Role) domain.Metadata { return item.Metadata })
	sortByMetadata(state.RoleBindings, func(item domain.RoleBinding) domain.Metadata { return item.Metadata })
	sortByMetadata(state.ClusterRoleBindings, func(item domain.RoleBinding) domain.Metadata { return item.Metadata })
	sortByMetadata(state.NetworkPolicies, func(item domain.NetworkPolicy) domain.Metadata { return item.Metadata })
	sortByMetadata(state.ValidatingAdmissionPolicies, func(item domain.ValidatingAdmissionPolicy) domain.Metadata { return item.Metadata })
	sortByMetadata(state.ValidatingAdmissionPolicyBindings, func(item domain.ValidatingAdmissionPolicyBinding) domain.Metadata { return item.Metadata })
	sortByMetadata(state.ValidatingWebhookConfigurations, func(item domain.ValidatingWebhookConfiguration) domain.Metadata { return item.Metadata })
}

func sortByMetadata[T any](items []T, metadata func(T) domain.Metadata) {
	sort.SliceStable(items, func(left, right int) bool {
		leftMetadata := metadata(items[left])
		rightMetadata := metadata(items[right])
		if leftMetadata.Namespace != rightMetadata.Namespace {
			return leftMetadata.Namespace < rightMetadata.Namespace
		}
		return leftMetadata.Name < rightMetadata.Name
	})
}
