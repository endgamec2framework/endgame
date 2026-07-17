package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ── SharpHound JSON structures ────────────────────────────────────────────────

type bhMeta struct {
	Type    string `json:"type"`
	Count   int    `json:"count"`
	Version int    `json:"version"`
}

// bhMember covers v3 (MemberId/MemberType) and v4/CE (ObjectIdentifier/ObjectType).
type bhMember struct {
	ObjectIdentifier string `json:"ObjectIdentifier"` // v4/CE
	ObjectType       string `json:"ObjectType"`       // v4/CE
	MemberID         string `json:"MemberId"`         // v3
	MemberType       string `json:"MemberType"`       // v3
}

func (m bhMember) sid() string {
	if m.ObjectIdentifier != "" {
		return m.ObjectIdentifier
	}
	return m.MemberID
}

// bhMemberList unmarshals v3 flat arrays and v4/CE {Results:[...]} wrappers.
type bhMemberList struct{ Members []bhMember }

func (l *bhMemberList) UnmarshalJSON(data []byte) error {
	var flat []bhMember
	if err := json.Unmarshal(data, &flat); err == nil {
		l.Members = flat
		return nil
	}
	var wrapped struct {
		Results []bhMember `json:"Results"`
	}
	if err := json.Unmarshal(data, &wrapped); err != nil {
		return err
	}
	l.Members = wrapped.Results
	return nil
}

// bhSessionList unmarshals v3 flat arrays and v4/CE {Results:[...]} wrappers.
type bhSessionList struct{ Sessions []bhSession }

func (l *bhSessionList) UnmarshalJSON(data []byte) error {
	var flat []bhSession
	if err := json.Unmarshal(data, &flat); err == nil {
		l.Sessions = flat
		return nil
	}
	var wrapped struct {
		Results []bhSession `json:"Results"`
	}
	if err := json.Unmarshal(data, &wrapped); err != nil {
		return err
	}
	l.Sessions = wrapped.Results
	return nil
}

// bhSession covers SharpHound v3/v4 (UserId/ComputerId) and CE (UserSID/ComputerSID).
type bhSession struct {
	UserSID     string `json:"UserSID"`
	ComputerSID string `json:"ComputerSID"`
	UserID      string `json:"UserId"`
	ComputerID  string `json:"ComputerId"`
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
	LocalAdmins        bhMemberList  `json:"LocalAdmins"`
	RemoteDesktopUsers bhMemberList  `json:"RemoteDesktopUsers"`
	DcomUsers          bhMemberList  `json:"DcomUsers"`
	PSRemoteUsers      bhMemberList  `json:"PSRemoteUsers"`
	Sessions           bhSessionList `json:"Sessions"`
	PrivilegedSessions bhSessionList `json:"PrivilegedSessions"`
	AllowedToDelegate  []bhMember    `json:"AllowedToDelegate"`
	AllowedToAct       []bhMember    `json:"AllowedToAct"`
}

type bhUser struct {
	ObjectIdentifier  string     `json:"ObjectIdentifier"`
	Properties        struct {
		Name        string `json:"name"`
		Domain      string `json:"domain"`
		Enabled     bool   `json:"enabled"`
		AdminCount  bool   `json:"admincount"`
		Description string `json:"description"`
	} `json:"Properties"`
	MemberOf          []bhMember `json:"MemberOf"`
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
		TargetDomainSid  string      `json:"TargetDomainSid"`
		TargetDomainName string      `json:"TargetDomainName"`
		IsTransitive     bool        `json:"IsTransitive"`
		TrustDirection   int         `json:"TrustDirection"`
		TrustType        interface{} `json:"TrustType"` // v3=int, v4=string
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
	// Strip UTF-8 BOM emitted by SharpHound v3
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})

	// Parse envelope — v4/CE uses "data" key; v3 uses the type name as key
	var envelope struct {
		Meta      bhMeta          `json:"meta"`
		Data      json.RawMessage `json:"data"`
		Computers json.RawMessage `json:"computers"`
		Users     json.RawMessage `json:"users"`
		Groups    json.RawMessage `json:"groups"`
		Domains   json.RawMessage `json:"domains"`
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

	// Resolve the data payload: prefer "data" key (v4/CE), fall back to type-named key (v3)
	resolve := func(v3key json.RawMessage) json.RawMessage {
		if len(envelope.Data) > 0 && string(envelope.Data) != "null" {
			return envelope.Data
		}
		return v3key
	}

	switch t {
	case "computers":
		bhParseComputers(resolve(envelope.Computers), g)
	case "users":
		bhParseUsers(resolve(envelope.Users), g)
	case "groups":
		bhParseGroups(resolve(envelope.Groups), g)
	case "domains":
		bhParseDomains(resolve(envelope.Domains), g)
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
		for _, la := range c.LocalAdmins.Members {
			if sid := la.sid(); sid != "" {
				g.Edges = append(g.Edges, &BHEdge{SourceSID: sid, TargetSID: c.ObjectIdentifier, EdgeType: "AdminTo"})
			}
		}
		for _, rdp := range c.RemoteDesktopUsers.Members {
			if sid := rdp.sid(); sid != "" {
				g.Edges = append(g.Edges, &BHEdge{SourceSID: sid, TargetSID: c.ObjectIdentifier, EdgeType: "CanRDP"})
			}
		}
		for _, dcom := range c.DcomUsers.Members {
			if sid := dcom.sid(); sid != "" {
				g.Edges = append(g.Edges, &BHEdge{SourceSID: sid, TargetSID: c.ObjectIdentifier, EdgeType: "ExecuteDCOM"})
			}
		}
		for _, ps := range c.PSRemoteUsers.Members {
			if sid := ps.sid(); sid != "" {
				g.Edges = append(g.Edges, &BHEdge{SourceSID: sid, TargetSID: c.ObjectIdentifier, EdgeType: "CanPSRemote"})
			}
		}
		for _, s := range c.Sessions.Sessions {
			userSID := s.UserSID
			if userSID == "" {
				userSID = s.UserID
			}
			if userSID != "" {
				g.Edges = append(g.Edges, &BHEdge{SourceSID: c.ObjectIdentifier, TargetSID: userSID, EdgeType: "HasSession"})
			}
		}
		for _, s := range c.PrivilegedSessions.Sessions {
			userSID := s.UserSID
			if userSID == "" {
				userSID = s.UserID
			}
			if userSID != "" {
				g.Edges = append(g.Edges, &BHEdge{SourceSID: c.ObjectIdentifier, TargetSID: userSID, EdgeType: "HasSession"})
			}
		}
		for _, d := range c.AllowedToDelegate {
			if sid := d.sid(); sid != "" {
				g.Edges = append(g.Edges, &BHEdge{SourceSID: c.ObjectIdentifier, TargetSID: sid, EdgeType: "AllowedToDelegate"})
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
			if sid := mo.sid(); sid != "" {
				g.Edges = append(g.Edges, &BHEdge{SourceSID: u.ObjectIdentifier, TargetSID: sid, EdgeType: "MemberOf"})
			}
		}
		for _, d := range u.AllowedToDelegate {
			if sid := d.sid(); sid != "" {
				g.Edges = append(g.Edges, &BHEdge{SourceSID: u.ObjectIdentifier, TargetSID: sid, EdgeType: "AllowedToDelegate"})
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
			if sid := m.sid(); sid != "" {
				g.Edges = append(g.Edges, &BHEdge{SourceSID: sid, TargetSID: grp.ObjectIdentifier, EdgeType: "MemberOf"})
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

// ── Auto-detection ────────────────────────────────────────────────────────────

// isSharpHoundZIP returns true if data is a ZIP containing SharpHound JSON files.
func isSharpHoundZIP(data []byte) bool {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return false
	}
	for _, f := range r.File {
		name := strings.ToLower(f.Name)
		if strings.HasSuffix(name, "_computers.json") ||
			strings.HasSuffix(name, "_users.json") ||
			strings.HasSuffix(name, "_groups.json") ||
			strings.HasSuffix(name, "_domains.json") ||
			name == "computers.json" || name == "users.json" ||
			name == "groups.json" || name == "domains.json" {
			return true
		}
	}
	return false
}

// CheckAndPromptBH detects a SharpHound ZIP in an uploaded file and broadcasts
// a BH_IMPORT_PROMPT event so the GUI can offer an import button to the operator.
// It does NOT import automatically.
func (s *Server) CheckAndPromptBH(agentID, filename string, data []byte) {
	if !strings.HasSuffix(strings.ToLower(filename), ".zip") {
		return
	}
	if !isSharpHoundZIP(data) {
		return
	}
	// Parse to preview node/edge counts without persisting
	g, err := ParseBloodHoundZIP(data)
	if err != nil || len(g.Nodes) == 0 {
		return
	}
	s.printf("[BH] SharpHound ZIP detectado: %s (%d nodos, %d edges)\n", filename, len(g.Nodes), len(g.Edges))
	BroadcastGUI("BH_IMPORT_PROMPT", agentID, fmt.Sprintf(
		`{"filename":%q,"agent_id":%q,"nodes":%d,"edges":%d}`,
		filename, agentID, len(g.Nodes), len(g.Edges),
	))
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
