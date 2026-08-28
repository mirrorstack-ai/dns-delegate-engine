package intent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// 🔴 THIS FILE IS THE ENFORCEMENT OF docs/DESIGN.md §5, AND §5 IS THE WHOLE
// POINT OF THE REBUILD.
//
// The old surface took `records []dnsplan.Record`, and every byte that reached a
// customer's zone came out of that field. Anchor containment bounds a record's
// NAME and nothing bounds its VALUE, so a caller could point a session hostname
// inside the customer's own domain at somebody else's origin, or publish a third
// party's ACME token, with every check in this repository passing.
//
// A comment saying "do not add a records field" would not survive a year. These
// tests do: they walk every request struct by reflection and fail on any type
// they do not recognise, so a map, a json.RawMessage, a nested struct or an
// `any` is rejected BY DEFAULT rather than by somebody having thought of it in
// advance. They then parse this package's own source and fail if a `…Request`
// type exists that the walk never saw — because the realistic way this contract
// gets broken is not by adding a forbidden field to a policed struct, it is by
// adding a new struct nobody remembered to police.

// allowedFieldTypes is the closed vocabulary of §5.
//
// 🔴 MATCHED EXACTLY, NOT BY KIND. A named string type — `type Lane string` —
// has reflect.Kind String and would pass a kind check, while being free to carry
// an UnmarshalJSON that accepts an object and expands it into anything at all.
// That is a decode hook, which is precisely the thing this table exists to keep
// out of the request surface. Exact types have no hooks.
var allowedFieldTypes = map[reflect.Type]struct{}{
	reflect.TypeOf(""):            {},
	reflect.TypeOf(false):         {},
	reflect.TypeOf(int64(0)):      {},
	reflect.TypeOf([]string(nil)): {},
}

// forbiddenFieldNames are the names that would reintroduce the defect even
// though each one is a perfectly ordinary string.
//
// A `Value string` on a request passes every type check in this file and hands
// the caller back exactly the authority §1 removed. So the names are refused as
// well as the types, on the Go field name AND on the JSON tag, because the wire
// contract is the tag and a mismatched pair is how a forbidden field arrives
// wearing an allowed name.
var forbiddenFieldNames = []string{
	"records", "value", "target", "proxied",
	"certificateid", "hostnameid", "ownershiptoken", "expiry", "stage",
}

func TestEveryRequestFieldIsInTheDeclaredVocabulary(t *testing.T) {
	for _, request := range requestTypes {
		typ := reflect.TypeOf(request)
		if typ.Kind() != reflect.Struct {
			t.Fatalf("%s is not a struct", typ)
		}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			switch {
			case field.Anonymous:
				// An embedded type smuggles its own fields onto the wire without
				// any of them appearing in this walk.
				t.Fatalf("%s.%s is embedded; §5 request fields are named and flat", typ.Name(), field.Name)
			case !field.IsExported():
				// An unexported field cannot be decoded, so it is a field that
				// silently is not there — a contract that reads one way and
				// behaves another.
				t.Fatalf("%s.%s is unexported and can never be decoded", typ.Name(), field.Name)
			}
			if _, ok := allowedFieldTypes[field.Type]; !ok {
				t.Fatalf("%s.%s is %s, which is not one of string, bool, int64, []string (docs/DESIGN.md §5)",
					typ.Name(), field.Name, field.Type)
			}
			tag := jsonName(field)
			if tag == "" {
				t.Fatalf("%s.%s has no json tag; the wire name is the contract and must be written down",
					typ.Name(), field.Name)
			}
			for _, forbidden := range forbiddenFieldNames {
				if strings.EqualFold(field.Name, forbidden) || strings.EqualFold(tag, forbidden) {
					t.Fatalf("%s.%s (json %q) is a forbidden field name: there is no records field, no value, "+
						"no target, no proxy flag, no certificate id, no hostname id, no ownership token, "+
						"no expiry and no stage on this surface",
						typ.Name(), field.Name, tag)
				}
			}
		}
	}
}

// 🔴 THE GUARD ON THE GUARD. A new request struct that is missing from
// requestTypes is not policed by the test above at all, and nothing else in the
// build would notice. So the package's own source is parsed and every declared
// `…Request` type is required to appear in the list.
func TestEveryRequestTypeInThePackageIsPoliced(t *testing.T) {
	listed := make(map[string]bool, len(requestTypes))
	for _, request := range requestTypes {
		listed[reflect.TypeOf(request).Name()] = true
	}
	declared := declaredRequestTypes(t)
	if len(declared) == 0 {
		t.Fatal("no request types were found in the package source; the parser is not reading what it thinks it is")
	}
	for _, name := range declared {
		if !listed[name] {
			t.Fatalf("%s is declared in this package but missing from requestTypes, so nothing checks its fields "+
				"against docs/DESIGN.md §5", name)
		}
	}
	for name := range listed {
		found := false
		for _, declared := range declared {
			if declared == name {
				found = true
			}
		}
		if !found {
			t.Fatalf("requestTypes names %s, which is not declared in this package's non-test source", name)
		}
	}
}

// A request may not carry the OAuth state either, and that absence is a
// behaviour rather than an omission: Authorize MINTS the state, so a caller
// cannot author one for a registration it is not holding. It is checked by name
// here because the type check above would happily accept `State string`, and it
// is only forbidden on the way IN — CompleteRequest.State is the sealed envelope
// coming back, which is the one place it belongs.
func TestAuthorizeCannotBeHandedAState(t *testing.T) {
	typ := reflect.TypeOf(AuthorizeRequest{})
	for i := 0; i < typ.NumField(); i++ {
		if strings.EqualFold(typ.Field(i).Name, "state") {
			t.Fatal("AuthorizeRequest carries a state field; Authorize mints the state and must not accept one")
		}
	}
	if _, ok := reflect.TypeOf(CompleteRequest{}).FieldByName("State"); !ok {
		t.Fatal("CompleteRequest must echo the sealed state back")
	}
}

// 🔴 Complete takes no identity, no lane and no domain: all three come out of
// the sealed state. Two requests whose fields are checked against each other can
// be made to disagree; one sealed envelope cannot disagree with itself.
func TestCompleteCarriesNoIdentityLaneOrDomain(t *testing.T) {
	typ := reflect.TypeOf(CompleteRequest{})
	for i := 0; i < typ.NumField(); i++ {
		switch strings.ToLower(typ.Field(i).Name) {
		case "orgid", "appid", "identity", "lane", "domain", "hostname", "anchor":
			t.Fatalf("CompleteRequest.%s: complete() takes none of these — they come out of the sealed state",
				typ.Field(i).Name)
		}
	}
}

func jsonName(field reflect.StructField) string {
	tag, ok := field.Tag.Lookup("json")
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(tag, ",")
	return name
}

// declaredRequestTypes parses every non-test source file in this package and
// returns the names of the types whose names end in "Request".
//
// os.ReadDir plus parser.ParseFile rather than parser.ParseDir: the latter is
// deprecated, and a test that emits a deprecation warning is a test somebody
// eventually deletes.
func declaredRequestTypes(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	fset := token.NewFileSet()
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok || genDecl.Tok != token.TYPE {
				continue
			}
			for _, spec := range genDecl.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok || !strings.HasSuffix(typeSpec.Name.Name, "Request") {
					continue
				}
				names = append(names, typeSpec.Name.Name)
			}
		}
	}
	return names
}
