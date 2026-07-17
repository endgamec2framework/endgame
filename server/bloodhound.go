package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// ── SharpHound JSON structures ────────────────────────────────────────────────

type bhMeta struct {
	Type    string `json:"type"`
	Count   int    `json:"count"`
	Version int    `json:"version"`
}

// bhMember covers both LocalAdmins / RemoteDesktopUsers entries and group Members.
type bhMember struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

// bhSession covers SharpHound v4 (UserId/ComputerId) and CE (UserSID/ComputerSID).
type bhSession struct {
	UserSID    string `json:"UserSID"`
	ComputerSID string `json:"ComputerSID"`
	UserID     string `json:"UserId"`
	ComputerID string `json:"ComputerId"`
}

type bhComputer struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	Properties       struct {
		Name                    string `json:"name"`
		Domain                  string `json:"domain"`
		Enabled                 bool   `json:"enabled"`
		UnconstrainedDelegation bool   `json:"unconstraineddelegation"`
		TrustedToAuth           bool   `json:"trustedtoauth"`
		HasLAPS                 bool   `json:"haslaps"`
		OperatingSystem         string `json:"operatingsystem"`
	} `json:"Properties"`
	LocalAdmins struct {
		Results []bhMember `json:"Results"`
	} `json:"LocalAdmins"`
	RemoteDesktopUsers struct {
		Results []bhMember `json:"Results"`
	} `json:"RemoteDesktopUsers"`
	DcomUsers struct {
		Results []bhMember `json:"Results"`
	} `json:"DcomUsers"`
	PSRemoteUsers struct {
		Results []bhMember `json:"Results"`
	} `json:"PSRemoteUsers"`
	Sessions struct {
		Results []bhSession `json:"Results"`
	} `json:"Sessions"`
	PrivilegedSessions struct {
		Results []bhSession `json:"Results"`
	} `json:"PrivilegedSessions"`
	AllowedToDelegate []bhMember `json:"AllowedToDelegate"`
	AllowedToAct      []bhMember `json:"AllowedToAct"`
}

type bhUser struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	Properties       struct {
		Name        string `json:"name"`
		Domain      string `json:"domain"`
		Enabled     bool   `json:"enabled"`
		AdminCount  bool   `json:"admincount"`
		Description string `json:"description"`
	} `json:"Properties"`
	MemberOf         []bhMember `json:"MemberOf"`
	AllowedToDelegate []bhMember `json:"AllowedToDelegate"`
}

type bhGroup struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	Properties       struct {
		Name       string `json:"name"`
		Domain     string `json:"domain"`
		AdminCount bool   `json:"admincount"`
	} `json:"Properties"`
	Members []bhMember `json:"Members"`
}

type bhDomain struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	Properties       struct {
		Name            string `json:"name"`
		Domain          string `json:"domain"`
		FunctionalLevel string `json:"functionallevel"`
	} `json:"Properties"`
	Trusts []struct {
		TargetDomainSid  string `json:"TargetDomainSid"`
		TargetDomainName string `json:"TargetDomainName"`
		IsTransitive     bool   `json:"IsTransitive"`
		TrustDirection   int    `json:"TrustDirection"`
		TrustType        string `json:"TrustType"`
	} `json:"Trusts"`
}

// ── Output types stored in DB ─────────────────────────────────────────────────

// BHNode is a node to store in bh_nodes.
type BHNode struct {
	SID    string `json:"sid"`
	Name   string `json:"name"`
	Type   string `json:"type"`   // computer | user | group | domain | ou
	Domain string `json:"domain"`
	Props  string `json:"props"`  // JSON: os, enabled, admincount, unconstrained_delegation…
}

// BHEdge is a relationship to store in bh_edges.
type BHEdge struct {
	ID        int64  `json:"id,omitempty"`
	SourceSID string `json:"source_sid"`
	TargetSID string `json:"target_sid"`
	EdgeType  string `json:"edge_type"` // AdminTo | MemberOf | HasSession | CanRDP | AllowedToDelegate | CanPSRemote | ExecuteDCOM
}

// BHGraph is the result of parsing one or more SharpHound files.
type BHGraph struct {
	Nodes  []*BHNode
	Edges  []*BHEdge
	Domain string
}

// ── Parsing ───────────────────────────────────────────────────────────────────

// ParseBloodHoundZIP parses a SharpHound ZIP archive and returns the AD graph.
func ParseBloodHoundZIP(data []byte) (*BHGraph, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	g := &BHGraph{}
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			continue
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}
		bhParseFile(strings.ToLower(f.Name), content, g)
	}
	dedupeEdges(g)
	return g, nil
}

// ParseBloodHoundJSON parses a single SharpHound JSON file.
func ParseBloodHoundJSON(filename string, data []byte) (*BHGraph, error) {
	g := &BHGraph{}
	bhParseFile(strings.ToLower(filename), data, g)
	dedupeEdges(g)
	return g, nil
}

func bhParseFile(name string, data []byte, g *BHGraph) {
	var envelope struct {
		Meta bhMeta          `json:"meta"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return
	}
	t := envelope.Meta.Type
	if t == "" {
		switch {
		case strings.Contains(name, "computer"):
			t = "computers"
		case strings.Contains(name, "user"):
			t = "users"
		case strings.Contains(name, "group"):
			t = "groups"
		case strings.Contains(name, "domain"):
			t = "domains"
		}
	}

	switch t {
	case "computers":
		bhParseComputers(envelope.Data, g)
	case "users":
		bhParseUsers(envelope.Data, g)
	case "groups":
		bhParseGroups(envelope.Data, g)
	case "domains":
		bhParseDomains(envelope.Data, g)
	}
}

func bhParseComputers(raw json.RawMessage, g *BHGraph) {
	var computers []bhComputer
	if err := json.Unmarshal(raw, &computers); err != nil {
		return
	}
	for i := range computers {
		c := &computers[i]
		if c.ObjectIdentifier == "" {
			continue
		}
		props, _ := json.Marshal(map[string]any{
			"os":                      c.Properties.OperatingSystem,
			"enabled":                 c.Properties.Enabled,
			"unconstrained_delegation": c.Properties.UnconstrainedDelegation,
			"trusted_to_auth":         c.Properties.TrustedToAuth,
			"haslaps":                 c.Properties.HasLAPS,
		})
		g.Nodes = append(g.Nodes, &BHNode{
			SID:    c.ObjectIdentifier,
			Name:   c.Properties.Name,
			Type:   "computer",
			Domain: c.Properties.Domain,
			Props:  string(props),
		})
		for _, la := range c.LocalAdmins.Results {
			if la.ObjectIdentifier != "" {
				g.Edges = append(g.Edges, &BHEdge{SourceSID: la.ObjectIdentifier, TargetSID: c.ObjectIdentifier, EdgeType: "AdminTo"})
			}
		}
		for _, rdp := range c.RemoteDesktopUsers.Results {
			if rdp.ObjectIdentifier != "" {
				g.Edges = append(g.Edges, &BHEdge{SourceSID: rdp.ObjectIdentifier, TargetSID: c.ObjectIdentifier, EdgeType: "CanRDP"})
			}
		}
		for _, dcom := range c.DcomUsers.Results {
			if dcom.ObjectIdentifier != "" {
				g.Edges = append(g.Edges, &BHEdge{SourceSID: dcom.ObjectIdentifier, TargetSID: c.ObjectIdentifier, EdgeType: "ExecuteDCOM"})
			}
		}
		for _, ps := range c.PSRemoteUsers.Results {
			if ps.ObjectIdentifier != "" {
				g.Edges = append(g.Edges, &BHEdge{SourceSID: ps.ObjectIdentifier, TargetSID: c.ObjectIdentifier, EdgeType: "CanPSRemote"})
			}
		}
		for _, s := range c.Sessions.Results {
			userSID := s.UserSID
			if userSID == "" {
				userSID = s.UserID
			}
			if userSID != "" {
				g.Edges = append(g.Edges, &BHEdge{SourceSID: c.ObjectIdentifier, TargetSID: userSID, EdgeType: "HasSession"})
			}
		}
		for _, s := range c.PrivilegedSessions.Results {
			userSID := s.UserSID
			if userSID == "" {
				userSID = s.UserID
			}
			if userSID != "" {
				g.Edges = append(g.Edges, &BHEdge{SourceSID: c.ObjectIdentifier, TargetSID: userSID, EdgeType: "HasSession"})
			}
		}
		for _, d := range c.AllowedToDelegate {
			if d.ObjectIdentifier != "" {
				g.Edges = append(g.Edges, &BHEdge{SourceSID: c.ObjectIdentifier, TargetSID: d.ObjectIdentifier, EdgeType: "AllowedToDelegate"})
			}
		}
	}
}

func bhParseUsers(raw json.RawMessage, g *BHGraph) {
	var users []bhUser
	if err := json.Unmarshal(raw, &users); err != nil {
		return
	}
	for i := range users {
		u := &users[i]
		if u.ObjectIdentifier == "" {
			continue
		}
		props, _ := json.Marshal(map[string]any{
			"enabled":    u.Properties.Enabled,
			"admincount": u.Properties.AdminCount,
		})
		g.Nodes = append(g.Nodes, &BHNode{
			SID:    u.ObjectIdentifier,
			Name:   u.Properties.Name,
			Type:   "user",
			Domain: u.Properties.Domain,
			Props:  string(props),
		})
		for _, mo := range u.MemberOf {
			if mo.ObjectIdentifier != "" {
				g.Edges = append(g.Edges, &BHEdge{SourceSID: u.ObjectIdentifier, TargetSID: mo.ObjectIdentifier, EdgeType: "MemberOf"})
			}
		}
		for _, d := range u.AllowedToDelegate {
			if d.ObjectIdentifier != "" {
				g.Edges = append(g.Edges, &BHEdge{SourceSID: u.ObjectIdentifier, TargetSID: d.ObjectIdentifier, EdgeType: "AllowedToDelegate"})
			}
		}
	}
}

func bhParseGroups(raw json.RawMessage, g *BHGraph) {
	var groups []bhGroup
	if err := json.Unmarshal(raw, &groups); err != nil {
		return
	}
	for i := range groups {
		grp := &groups[i]
		if grp.ObjectIdentifier == "" {
			continue
		}
		props, _ := json.Marshal(map[string]any{
			"admincount": grp.Properties.AdminCount,
		})
		g.Nodes = append(g.Nodes, &BHNode{
			SID:    grp.ObjectIdentifier,
			Name:   grp.Properties.Name,
			Type:   "group",
			Domain: grp.Properties.Domain,
			Props:  string(props),
		})
		for _, m := range grp.Members {
			if m.ObjectIdentifier != "" {
				g.Edges = append(g.Edges, &BHEdge{SourceSID: m.ObjectIdentifier, TargetSID: grp.ObjectIdentifier, EdgeType: "MemberOf"})
			}
		}
	}
}

func bhParseDomains(raw json.RawMessage, g *BHGraph) {
	var domains []bhDomain
	if err := json.Unmarshal(raw, &domains); err != nil {
		return
	}
	for i := range domains {
		d := &domains[i]
		if d.ObjectIdentifier == "" {
			continue
		}
		props, _ := json.Marshal(map[string]any{
			"functional_level": d.Properties.FunctionalLevel,
		})
		name := d.Properties.Name
		if name == "" {
			name = d.Properties.Domain
		}
		g.Nodes = append(g.Nodes, &BHNode{
			SID:    d.ObjectIdentifier,
			Name:   name,
			Type:   "domain",
			Domain: d.Properties.Domain,
			Props:  string(props),
		})
		if g.Domain == "" {
			g.Domain = d.Properties.Domain
		}
	}
}

func dedupeEdges(g *BHGraph) {
	seen := make(map[string]bool, len(g.Edges))
	out := g.Edges[:0]
	for _, e := range g.Edges {
		key := e.SourceSID + "|" + e.TargetSID + "|" + e.EdgeType
		if !seen[key] {
			seen[key] = true
			out = append(out, e)
		}
	}
	g.Edges = out
}
