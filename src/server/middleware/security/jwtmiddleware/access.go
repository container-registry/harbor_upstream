package jwtmiddleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/goharbor/harbor/src/common/rbac"
	"github.com/goharbor/harbor/src/lib"
	"github.com/goharbor/harbor/src/lib/log"
)

type target int

const (
	Login target = iota
	Catalog
	Repository
)

func (t target) String() string {
	return []string{"login", "catalog", "repository"}[t]
}

type Access struct {
	Target target
	Name   string
	Action rbac.Action
}

func (a Access) ScopeStr(ctx context.Context) string {
	logger := log.G(ctx)
	if a.Target != Repository {
		// Currently we do not support providing a token to list catalog
		return ""
	}
	act := ""
	switch a.Action {
	case rbac.ActionPull:
		act = "pull"
	case rbac.ActionPush:
		act = "pull,push"
	case rbac.ActionDelete:
		act = "delete"
	default:
		logger.Warningf("Invalid action in access: %s, returning empty scope", a.Action)
		return ""
	}
	return fmt.Sprintf("repository:%s:%s", a.Name, act)
}

func GetAction(req *http.Request) rbac.Action {
	actions := map[string]rbac.Action{
		http.MethodPost:   rbac.ActionPush,
		http.MethodPatch:  rbac.ActionPush,
		http.MethodPut:    rbac.ActionPush,
		http.MethodGet:    rbac.ActionPull,
		http.MethodHead:   rbac.ActionPull,
		http.MethodDelete: rbac.ActionDelete,
	}
	if action, ok := actions[req.Method]; ok {
		return action
	}
	return ""
}

func AccessList(req *http.Request) []Access {
	l := make([]Access, 0, 3)
	// for _catalog
	if lib.V2CatalogURLRe.MatchString(req.URL.Path) {
		l = append(l, Access{
			Target: Catalog,
		})
		return l
	}
	// for repository
	none := lib.ArtifactInfo{}
	if a := lib.GetArtifactInfo(req.Context()); a != none {
		action := GetAction(req)
		if action == "" {
			return l
		}
		l = append(l, Access{
			Target: Repository,
			Name:   a.Repository,
			Action: action,
		})
		// kumar keep an eye on the below condition
		if req.Method == http.MethodPost && a.BlobMountRepository != "" { // need pull access for blob mount
			l = append(l, Access{
				Target: Repository,
				Name:   a.BlobMountRepository,
				Action: rbac.ActionPull,
			})
		}
	}
	return l
}
