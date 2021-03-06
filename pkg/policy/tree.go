// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"fmt"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/policy/api"
)

// Tree overall policy tree.
type Tree struct {
	// Mutex protects the whole policy tree
	Mutex sync.RWMutex
	Root  *Node
}

// NewTree allocates and initializes a new policy tree
func NewTree() *Tree {
	tree := &Tree{}
	return tree
}

func canConsume(root *Node, ctx *SearchContext) api.ConsumableDecision {
	ctx.Depth++
	decision := api.UNDECIDED
	nmatch := 0
	defer func() {
		if nmatch != 0 {
			ctx.Depth--
		}
	}()

	for _, child := range root.Children {
		if child.Covers(ctx) {
			nmatch++
			ctx.PolicyTrace("Coverage found in [%s], processing rules...\n", child.path)
			ctx.Depth++
			switch child.Allows(ctx) {
			case api.DENY:
				ctx.Depth--
				return api.DENY
			case api.ALWAYS_ACCEPT:
				ctx.Depth--
				return api.ALWAYS_ACCEPT
			case api.ACCEPT:
				decision = api.ACCEPT
			}
			ctx.Depth--
			ctx.PolicyTrace("No conclusion in [%s] rules, current verdict: [%s]\n", child.path, decision)
		}
	}

	if nmatch == 0 {
		ctx.Depth--
		ctx.PolicyTrace("No matching children in [%s]\n", root.path)
		return decision
	}

	for _, child := range root.Children {
		if child.Covers(ctx) {
			switch canConsume(child, ctx) {
			case api.DENY:
				return api.DENY
			case api.ALWAYS_ACCEPT:
				return api.ALWAYS_ACCEPT
			case api.ACCEPT:
				decision = api.ACCEPT
			}
		}
	}

	return decision
}

// AllowsRLocked checks the ConsumableDecision of the given `SearchContext`.
// Must be called with the Mutex's tree at least RLocked.
func (t *Tree) AllowsRLocked(ctx *SearchContext) api.ConsumableDecision {
	ctx.PolicyTrace("NEW TRACE >> %s\n", ctx.String())

	var decision, subDecision api.ConsumableDecision
	// In absence of policy, deny
	if t.Root == nil {
		decision = api.DENY
		ctx.PolicyTrace("No policy loaded: [%s]\n", decision.String())
		goto end
	}

	decision = t.Root.Allows(ctx)
	ctx.PolicyTrace("Root's [%s] rules verdict: [%s]\n", t.Root.path, decision)
	switch decision {
	case api.ALWAYS_ACCEPT:
		decision = api.ACCEPT
		goto end
	case api.DENY:
		goto end
	}

	ctx.PolicyTrace("Searching in [%s]'s children that have the coverage for: [%s]\n", t.Root.path, ctx.To)
	subDecision = canConsume(t.Root, ctx)
	ctx.PolicyTrace("Root's [%s] children verdict: [%s]\n", t.Root.path, subDecision)
	switch subDecision {
	case api.ALWAYS_ACCEPT, api.ACCEPT:
		decision = api.ACCEPT
	case api.DENY:
		decision = api.DENY
	case api.UNDECIDED:
		if decision == api.UNDECIDED {
			decision = api.DENY
		}
	}

end:
	ctx.PolicyTrace("END TRACE << verdict: [%s]\n", strings.ToUpper(decision.String()))

	return decision
}

func (t *Tree) ResolveL4Policy(ctx *SearchContext) *L4Policy {
	result := NewL4Policy()

	ctx.PolicyTrace("Resolving L4 policy for context %+v\n", ctx)

	if t.Root != nil {
		t.Root.ResolveL4Policy(ctx, result)
	}

	ctx.PolicyTrace("Final tree L4 policy: %+v\n", result)
	return result
}

// LookupLocked returns a policy node and its parent for a given path.
// The `RootNodeName` is optional. If `path` is "", `node` will be the tree's
// root and `parent` will be `nil`.
//
// If `path` does not start with `RootNodeName`, it will be assumed `path` is a
// root's child. Thus, if `path` is a single node, the `parent` returned will be
// the tree's root.
func (t *Tree) LookupLocked(path string) (node, parent *Node) {
	// Empty tree
	if t.Root == nil {
		return nil, nil
	}

	path = removeRootPrefix(path)

	// "root." returns root node
	if path == "" {
		return t.Root, nil
	}

	node = t.Root
	parent = nil

	elements := strings.Split(path, NodePathDelimiter)
	for index, nodeName := range elements {
		if child, ok := node.Children[nodeName]; ok {
			parent = node
			node = child
		} else {
			// Return parent if we failed at last element
			if index == len(elements)-1 {
				return nil, node
			}
			return nil, nil
		}
	}

	return node, parent
}

// Add adds the provided policy node at the specified path.
func (t *Tree) Add(parentPath string, node *Node) (bool, error) {
	if node == nil {
		return false, nil
	}

	t.Mutex.Lock()
	defer t.Mutex.Unlock()

	return t.add(parentPath, node)
}

// add adds the provided policy node at the specified path. Must be called with
// t.Mutex locked.
func (t *Tree) add(parentPath string, node *Node) (bool, error) {
	var err error

	if parentPath, err = node.NormalizeNames(parentPath); err != nil {
		return false, err
	}

	modified := false

	if parentPath == RootNodeName && node.Name == RootNodeName {
		node.Path()
		if t.Root == nil {
			t.Root = node
			modified = true
		} else {
			if modified, err = t.Root.Merge(node); err != nil {
				return false, err
			}
			// If modified we need to resolve the tree's root
			if modified {
				return true, t.Root.ResolveTree()
			}
		}
	} else {
		absPath := JoinPath(parentPath, node.Name)
		_, parent := t.LookupLocked(absPath)
		if parent == nil {
			grandParentPath, parentName := SplitNodePath(parentPath)
			parent = NewNode(parentName, nil)
			_, err := t.add(grandParentPath, parent)
			if err != nil {
				return false, fmt.Errorf("unable to add parent's node for path '%s': %s", parentPath, err)
			}
		}

		if modified, err = parent.AddChild(node.Name, node); err != nil {
			return false, err
		}
	}

	if modified {
		return true, node.ResolveTree()
	}

	return modified, nil
}

func (t *Tree) deleteNode(node, parent *Node) {
	if node == t.Root {
		t.Root = nil
	} else if parent != nil {
		delete(parent.Children, node.Name)
	}
}

func (t *Tree) Delete(path string, coverage string) bool {
	t.Mutex.Lock()
	defer t.Mutex.Unlock()

	node, parent := t.LookupLocked(path)
	if node == nil {
		return false
	}

	// Deletion request of a specific rule of a node
	if coverage != "" {
		for i, pr := range node.Rules {
			if prCover256Sum, err := pr.CoverageSHA256Sum(); err == nil &&
				prCover256Sum == coverage {
				node.Rules = append(node.Rules[:i], node.Rules[i+1:]...)

				// If the rule was the last remaining, delete the node
				if !node.HasRules() {
					t.deleteNode(node, parent)
				}

				return true
			}
		}

		return false
	}

	// Deletion request for entire node
	t.deleteNode(node, parent)

	return true
}
