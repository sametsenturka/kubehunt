// Package workload provides deterministic workload targeting shared by rules.
package workload

import (
	"fmt"

	"github.com/sametsenturka/kubehunt/internal/domain"
)

// Target is a Pod or supported controller template that should be assessed.
type Target struct {
	Ref      domain.ResourceReference
	Spec     domain.PodSpec
	SpecPath string
}

// Container identifies a container and its canonical field location.
type Container struct {
	Value   domain.Container
	Field   string
	Display string
}

// Targets returns supported desired-state workloads and standalone Pods.
// Pods represented by collected Deployments, StatefulSets, or DaemonSets are
// suppressed so one configuration does not produce controller/Pod duplicates.
func Targets(state domain.ClusterState) []Target {
	result := make([]Target, 0, len(state.Pods)+len(state.Deployments)+len(state.StatefulSets)+len(state.DaemonSets))
	for _, item := range state.Deployments {
		result = append(result, targetForWorkload("Deployment", item))
	}
	for _, item := range state.StatefulSets {
		result = append(result, targetForWorkload("StatefulSet", item))
	}
	for _, item := range state.DaemonSets {
		result = append(result, targetForWorkload("DaemonSet", item))
	}
	for _, pod := range state.Pods {
		if podRepresentedByCollectedWorkload(pod, state) {
			continue
		}
		result = append(result, Target{Ref: reference("v1", "Pod", pod.Metadata), Spec: pod.Spec, SpecPath: "spec"})
	}
	return result
}

// Containers returns regular and init containers and optionally ephemeral
// containers, preserving canonical field paths for evidence.
func Containers(target Target, includeEphemeral bool) []Container {
	capacity := len(target.Spec.Containers) + len(target.Spec.InitContainers)
	if includeEphemeral {
		capacity += len(target.Spec.EphemeralContainers)
	}
	result := make([]Container, 0, capacity)
	for _, item := range target.Spec.Containers {
		result = append(result, Container{Value: item, Field: target.SpecPath + ".containers", Display: "container"})
	}
	for _, item := range target.Spec.InitContainers {
		result = append(result, Container{Value: item, Field: target.SpecPath + ".initContainers", Display: "initContainer"})
	}
	if includeEphemeral {
		for _, item := range target.Spec.EphemeralContainers {
			result = append(result, Container{Value: item, Field: target.SpecPath + ".ephemeralContainers", Display: "ephemeralContainer"})
		}
	}
	return result
}

func ContainerField(container Container, suffix string) string {
	return fmt.Sprintf("%s[name=%s].%s", container.Field, container.Value.Name, suffix)
}

func targetForWorkload(kind string, item domain.Workload) Target {
	return Target{Ref: reference("apps/v1", kind, item.Metadata), Spec: item.Template.Spec, SpecPath: "spec.template.spec"}
}

func reference(apiVersion, kind string, metadata domain.Metadata) domain.ResourceReference {
	return domain.ResourceReference{APIVersion: apiVersion, Kind: kind, Namespace: metadata.Namespace, Name: metadata.Name, UID: metadata.UID}
}

func podRepresentedByCollectedWorkload(pod domain.Pod, state domain.ClusterState) bool {
	for _, owner := range pod.Metadata.Owners {
		if !owner.Controller {
			continue
		}
		switch owner.Kind {
		case "StatefulSet":
			if workloadNamed(state.StatefulSets, pod.Metadata.Namespace, owner.Name) {
				return true
			}
		case "DaemonSet":
			if workloadNamed(state.DaemonSets, pod.Metadata.Namespace, owner.Name) {
				return true
			}
		case "ReplicaSet":
			for _, deployment := range state.Deployments {
				if deployment.Metadata.Namespace == pod.Metadata.Namespace && selectorMatches(deployment.Selector, pod.Metadata.Labels) {
					return true
				}
			}
		}
	}
	return false
}

func workloadNamed(workloads []domain.Workload, namespace, name string) bool {
	for _, item := range workloads {
		if item.Metadata.Namespace == namespace && item.Metadata.Name == name {
			return true
		}
	}
	return false
}

func selectorMatches(selector domain.LabelSelector, labels map[string]string) bool {
	for key, expected := range selector.MatchLabels {
		if labels[key] != expected {
			return false
		}
	}
	for _, expression := range selector.MatchExpressions {
		value, exists := labels[expression.Key]
		switch expression.Operator {
		case "In":
			if !exists || !contains(expression.Values, value) {
				return false
			}
		case "NotIn":
			if !exists || contains(expression.Values, value) {
				return false
			}
		case "Exists":
			if !exists {
				return false
			}
		case "DoesNotExist":
			if exists {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
