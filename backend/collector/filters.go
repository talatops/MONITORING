package collector

import "github.com/docker/docker/api/types/filters"

// newContainerFilter is a thin wrapper so docker.go doesn't have to import
// the filters package directly — keeps call-sites clean.
func newContainerFilter(m map[string][]string) filters.Args {
	f := filters.NewArgs()
	for key, values := range m {
		for _, v := range values {
			f.Add(key, v)
		}
	}
	return f
}
