// Package testcoverage contains the command to analyze test coverage for authorization models.
package testcoverage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	parser "github.com/openfga/language/pkg/go/transformer"

	checktest "github.com/openfga/openfga/internal/test/check"
)

const (
	modelFileFlag = "model-file"
	testFileFlag  = "test-file"
)

func NewTestCoverageCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test-coverage",
		Short: "Analyze test coverage for authorization model relations",
		Long: `Analyze test coverage for authorization model relations by comparing the model 
with test assertions to identify:
  - Relations that are not tested at all
  - Relations that only have positive test cases (allowed=true)
  - Relations that only have negative test cases (allowed=false)

This helps ensure comprehensive test coverage for your authorization models.`,
		RunE:  runTestCoverage,
		Args:  cobra.NoArgs,
	}

	flags := cmd.Flags()
	flags.String(modelFileFlag, "", "path to the model file (DSL format)")
	flags.String(testFileFlag, "", "path to the test file (YAML format)")

	_ = cmd.MarkFlagRequired(modelFileFlag)
	_ = cmd.MarkFlagRequired(testFileFlag)

	return cmd
}

// TestFile represents the structure of test YAML files
type TestFile struct {
	Tests []struct {
		Name   string `yaml:"name"`
		Stages []struct {
			Model                 string                 `yaml:"model"`
			CheckAssertions       []*checktest.Assertion `yaml:"checkAssertions"`
			ListObjectsAssertions []interface{}          `yaml:"listObjectsAssertions"`
			ListUsersAssertions   []interface{}          `yaml:"listUsersAssertions"`
		} `yaml:"stages"`
	} `yaml:"tests"`
}

// RelationCoverage tracks the coverage status of a relation
type RelationCoverage struct {
	TypeName         string `json:"type"`
	RelationName     string `json:"relation"`
	TestedDirectly   bool   `json:"tested_directly"`
	TestedIndirectly bool   `json:"tested_indirectly"`
	HasPositiveTest  bool   `json:"has_positive_test"`
	HasNegativeTest  bool   `json:"has_negative_test"`
}

// CoverageReport represents the complete coverage analysis
type CoverageReport struct {
	UntestedRelations []RelationCoverage `json:"untested_relations"`
	PartiallyTested   []RelationCoverage `json:"partially_tested"`
	FullyTested       []RelationCoverage `json:"fully_tested"`
}

func runTestCoverage(cmd *cobra.Command, _ []string) error {
	modelFile, _ := cmd.Flags().GetString(modelFileFlag)
	testFile, _ := cmd.Flags().GetString(testFileFlag)

	// Read model file
	modelContent, err := os.ReadFile(modelFile)
	if err != nil {
		return fmt.Errorf("failed to read model file: %w", err)
	}

	// Parse model
	model, err := parser.TransformDSLToProto(string(modelContent))
	if err != nil {
		return fmt.Errorf("failed to parse model: %w", err)
	}

	// Read test file
	testContent, err := os.ReadFile(testFile)
	if err != nil {
		return fmt.Errorf("failed to read test file: %w", err)
	}

	// Parse test file
	var testData TestFile
	err = yaml.Unmarshal(testContent, &testData)
	if err != nil {
		return fmt.Errorf("failed to parse test file: %w", err)
	}

	// Analyze coverage
	report, err := analyzeCoverage(model, &testData)
	if err != nil {
		return fmt.Errorf("failed to analyze coverage: %w", err)
	}

	// Output report
	marshalled, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("error generating report: %w", err)
	}
	fmt.Println(string(marshalled))

	return nil
}

func analyzeCoverage(model *openfgav1.AuthorizationModel, testData *TestFile) (*CoverageReport, error) {
	ctx := context.Background()

	// Extract all relations from model
	allRelations := extractAllRelations(model)

	// Track which relations are tested and how
	coverage := make(map[string]*RelationCoverage)
	for key := range allRelations {
		coverage[key] = allRelations[key]
	}

	// Analyze test assertions
	for _, test := range testData.Tests {
		for _, stage := range test.Stages {
			for _, assertion := range stage.CheckAssertions {
				if assertion.Tuple == nil {
					continue
				}

				objectType, err := getObjectType(assertion.Tuple.GetObject())
				if err != nil {
					continue
				}

				relation := assertion.Tuple.GetRelation()
				key := fmt.Sprintf("%s#%s", objectType, relation)

				if cov, exists := coverage[key]; exists {
					cov.TestedDirectly = true
					if assertion.Expectation {
						cov.HasPositiveTest = true
					} else {
						cov.HasNegativeTest = true
					}
				}
			}
		}
	}

	// Build computed relation graph to track indirect testing
	computedGraph := buildComputedGraph(model)

	// Propagate indirect testing information
	for key, cov := range coverage {
		if cov.TestedDirectly {
			// Mark all relations this one depends on as indirectly tested
			markIndirectlyTested(key, coverage, computedGraph)
		}
	}

	// Generate report
	report := &CoverageReport{
		UntestedRelations: []RelationCoverage{},
		PartiallyTested:   []RelationCoverage{},
		FullyTested:       []RelationCoverage{},
	}

	for _, cov := range coverage {
		if !cov.TestedDirectly && !cov.TestedIndirectly {
			report.UntestedRelations = append(report.UntestedRelations, *cov)
		} else if !cov.HasPositiveTest || !cov.HasNegativeTest {
			report.PartiallyTested = append(report.PartiallyTested, *cov)
		} else {
			report.FullyTested = append(report.FullyTested, *cov)
		}
	}

	_ = ctx // silence unused warning

	return report, nil
}

func extractAllRelations(model *openfgav1.AuthorizationModel) map[string]*RelationCoverage {
	relations := make(map[string]*RelationCoverage)

	for _, typeDef := range model.GetTypeDefinitions() {
		typeName := typeDef.GetType()

		for relationName := range typeDef.GetRelations() {
			key := fmt.Sprintf("%s#%s", typeName, relationName)
			relations[key] = &RelationCoverage{
				TypeName:     typeName,
				RelationName: relationName,
			}
		}
	}

	return relations
}

func buildComputedGraph(model *openfgav1.AuthorizationModel) map[string][]string {
	graph := make(map[string][]string)

	for _, typeDef := range model.GetTypeDefinitions() {
		typeName := typeDef.GetType()

		for relationName, rewrite := range typeDef.GetRelations() {
			key := fmt.Sprintf("%s#%s", typeName, relationName)

			// Find dependencies in the relation rewrite
			deps := extractDependencies(typeName, rewrite)
			graph[key] = deps
		}
	}

	return graph
}

func extractDependencies(typeName string, rewrite *openfgav1.Userset) []string {
	if rewrite == nil {
		return nil
	}

	var deps []string

	switch r := rewrite.Userset.(type) {
	case *openfgav1.Userset_This:
		// Direct assignment, no dependencies
		return nil
	case *openfgav1.Userset_ComputedUserset:
		// References another relation on same type
		relation := r.ComputedUserset.GetRelation()
		deps = append(deps, fmt.Sprintf("%s#%s", typeName, relation))
	case *openfgav1.Userset_TupleToUserset:
		// TTU relationship
		computedRelation := r.TupleToUserset.GetComputedUserset().GetRelation()
		deps = append(deps, fmt.Sprintf("%s#%s", typeName, computedRelation))
	case *openfgav1.Userset_Union:
		// Union of relations
		for _, child := range r.Union.GetChild() {
			deps = append(deps, extractDependencies(typeName, child)...)
		}
	case *openfgav1.Userset_Intersection:
		// Intersection of relations
		for _, child := range r.Intersection.GetChild() {
			deps = append(deps, extractDependencies(typeName, child)...)
		}
	case *openfgav1.Userset_Difference:
		// Difference (but not)
		deps = append(deps, extractDependencies(typeName, r.Difference.GetBase())...)
		deps = append(deps, extractDependencies(typeName, r.Difference.GetSubtract())...)
	}

	return deps
}

func markIndirectlyTested(relation string, coverage map[string]*RelationCoverage, graph map[string][]string) {
	visited := make(map[string]bool)
	var visit func(string)

	visit = func(rel string) {
		if visited[rel] {
			return
		}
		visited[rel] = true

		for _, dep := range graph[rel] {
			if cov, exists := coverage[dep]; exists && !cov.TestedDirectly {
				cov.TestedIndirectly = true
			}
			visit(dep)
		}
	}

	visit(relation)
}

func getObjectType(object string) (string, error) {
	for i, ch := range object {
		if ch == ':' {
			return object[:i], nil
		}
	}
	return "", fmt.Errorf("invalid object format: %s", object)
}
