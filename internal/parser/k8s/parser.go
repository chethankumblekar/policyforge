// Package k8s provides a Kubernetes manifest parser for PolicyForge.
//
// Every controller kind that wraps a pod template (Deployment, DaemonSet,
// StatefulSet, ReplicaSet, Job, CronJob) is flattened to the same
// pod-security attribute shape as a bare Pod — see podSpecFor — so one
// Rego rule pack (policies/k8s/pod-security) covers all of them without
// needing a rule per controller kind.
//
// Only pod-security-relevant fields are extracted (privileged containers,
// host networking, privilege escalation, resource limits, running as
// root): this is a policy scanner, not a general Kubernetes API client, so
// the full manifest schema isn't modeled.
package k8s

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/chethankumblekar/policyforge/internal/parser"
)

// Resource is the parsed shape shared across all IaC-language parsers.
type Resource = parser.Resource

// ParseDir walks dir and parses every *.yaml/*.yml file it finds, except
// inside Helm chart directories (any directory containing a Chart.yaml),
// which internal/parser/helm handles exclusively — a chart's raw
// templates/*.yaml files contain unrendered Go template syntax
// (`{{ .Values.x }}`), not valid Kubernetes manifests, and parsing them
// directly would at best duplicate what the Helm parser already
// extracts from the rendered output and at worst silently misread a
// value that happens to still parse as valid YAML once quoted.
func ParseDir(dir string) ([]Resource, error) {
	var all []Resource

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if _, statErr := os.Stat(filepath.Join(path, "Chart.yaml")); statErr == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		resources, ferr := ParseFile(path)
		if ferr != nil {
			return ferr
		}
		all = append(all, resources...)
		return nil
	})

	return all, err
}

// ParseFile parses every YAML document in path into a slice of Resource,
// one per Kubernetes object that has both apiVersion and kind set.
// Documents that aren't Kubernetes objects (or that don't parse as a
// mapping) are silently skipped rather than treated as errors, since a
// scan path may legitimately contain non-Kubernetes YAML.
func ParseFile(path string) ([]Resource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return ParseReader(f, path)
}

// ParseReader parses every YAML document read from r the same way
// ParseFile does, attributing every resource found to sourceFile. This is
// exported so other parsers whose YAML doesn't come from a single file on
// disk — e.g. internal/parser/helm, which parses `helm template`'s
// rendered stdout — can reuse the same Kubernetes-object extraction logic
// instead of duplicating it.
func ParseReader(r io.Reader, sourceFile string) ([]Resource, error) {
	dec := yaml.NewDecoder(r)
	var resources []Resource

	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(doc.Content) == 0 {
			continue
		}

		var raw map[string]interface{}
		if err := doc.Content[0].Decode(&raw); err != nil {
			continue
		}

		kind, _ := raw["kind"].(string)
		if kind == "" || raw["apiVersion"] == nil {
			continue
		}

		name := "unnamed"
		if meta, ok := raw["metadata"].(map[string]interface{}); ok {
			if n, ok := meta["name"].(string); ok && n != "" {
				name = n
			}
		}

		resources = append(resources, Resource{
			Type:       kind,
			Name:       kind + "/" + name,
			Attributes: podSecurityAttributes(kind, raw),
			File:       sourceFile,
			Line:       doc.Content[0].Line,
		})
	}

	return resources, nil
}

// podSpecFor navigates a decoded manifest down to its PodSpec-shaped map,
// regardless of which controller kind wraps it.
func podSpecFor(kind string, raw map[string]interface{}) map[string]interface{} {
	switch kind {
	case "Pod":
		return asMap(raw["spec"])
	case "CronJob":
		return dig(raw, "spec", "jobTemplate", "spec", "template", "spec")
	case "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job":
		return dig(raw, "spec", "template", "spec")
	default:
		return nil
	}
}

// podSecurityAttributes flattens the security-relevant fields of a pod
// spec into the flat string map the policy engine works with.
func podSecurityAttributes(kind string, raw map[string]interface{}) map[string]string {
	attrs := map[string]string{}

	spec := podSpecFor(kind, raw)
	if spec == nil {
		return attrs
	}

	hostNetwork, _ := spec["hostNetwork"].(bool)
	attrs["host_network"] = strconv.FormatBool(hostNetwork)

	podSC := asMap(spec["securityContext"])
	runAsNonRootFalse := explicitFalse(podSC["runAsNonRoot"])

	var privileged, allowPrivilegeEscalation, missingLimits bool

	containers := allContainers(spec)
	for _, c := range containers {
		sc := asMap(c["securityContext"])

		if b, ok := sc["privileged"].(bool); ok && b {
			privileged = true
		}
		if b, ok := sc["allowPrivilegeEscalation"].(bool); ok && b {
			allowPrivilegeEscalation = true
		}
		if explicitFalse(sc["runAsNonRoot"]) {
			runAsNonRootFalse = true
		}

		limits := dig(c, "resources", "limits")
		if len(limits) == 0 {
			missingLimits = true
		}
	}

	attrs["privileged"] = strconv.FormatBool(privileged)
	attrs["allow_privilege_escalation"] = strconv.FormatBool(allowPrivilegeEscalation)
	attrs["run_as_non_root_false"] = strconv.FormatBool(runAsNonRootFalse)
	attrs["missing_resource_limits"] = strconv.FormatBool(missingLimits)

	return attrs
}

func allContainers(spec map[string]interface{}) []map[string]interface{} {
	var out []map[string]interface{}
	for _, key := range []string{"containers", "initContainers"} {
		list, _ := spec[key].([]interface{})
		for _, c := range list {
			if m := asMap(c); m != nil {
				out = append(out, m)
			}
		}
	}
	return out
}

// explicitFalse reports whether v is the boolean false (as opposed to
// unset/absent, which is reported as false here — callers only want to
// flag an explicit, in-source `false`).
func explicitFalse(v interface{}) bool {
	b, ok := v.(bool)
	return ok && !b
}

func asMap(v interface{}) map[string]interface{} {
	m, _ := v.(map[string]interface{})
	return m
}

// dig walks a chain of nested map[string]interface{} keys, returning nil
// if any step along the path is missing or not a map.
func dig(m map[string]interface{}, path ...string) map[string]interface{} {
	cur := m
	for _, p := range path {
		next := asMap(cur[p])
		if next == nil {
			return nil
		}
		cur = next
	}
	return cur
}
