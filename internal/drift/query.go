package drift

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
)

// DefaultQuery builds a KQL query, scoped to the ARM types Compare knows
// how to diff, returning each resource's id/type/name/properties.
func DefaultQuery() string {
	types := make([]string, 0, len(normalizedTypeToARMType))
	for _, armType := range normalizedTypeToARMType {
		types = append(types, "'"+strings.ToLower(armType)+"'")
	}
	return "Resources\n| where type in~ (" + strings.Join(types, ", ") + ")\n| project id, type, name, properties"
}

// Query runs a Resource Graph KQL query scoped to subscriptionID,
// authenticating via azidentity.NewDefaultAzureCredential — which honors
// whatever the caller already has set up (az login session, environment
// variables, managed identity, workload identity, ...); PolicyForge never
// handles Azure credentials directly.
func Query(ctx context.Context, subscriptionID, kqlQuery string) ([]LiveResource, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("creating Azure credential: %w", err)
	}

	client, err := armresourcegraph.NewClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("creating Azure Resource Graph client: %w", err)
	}

	resultFormat := armresourcegraph.ResultFormatObjectArray
	resp, err := client.Resources(ctx, armresourcegraph.QueryRequest{
		Query:         &kqlQuery,
		Subscriptions: []*string{&subscriptionID},
		Options: &armresourcegraph.QueryRequestOptions{
			ResultFormat: &resultFormat,
		},
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("querying Azure Resource Graph: %w", err)
	}

	return parseRows(resp.Data)
}

// parseRows converts a QueryResponse.Data value (an objectArray-format
// Resource Graph result — a []interface{} of row objects) into
// LiveResource. Kept separate from Query so the row-shape parsing is
// testable without a live Azure Resource Graph call.
func parseRows(data any) ([]LiveResource, error) {
	rows, ok := data.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected Resource Graph response shape: %T (expected objectArray result format)", data)
	}

	resources := make([]LiveResource, 0, len(rows))
	for _, row := range rows {
		m, ok := row.(map[string]interface{})
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		typ, _ := m["type"].(string)
		name, _ := m["name"].(string)
		props, _ := m["properties"].(map[string]interface{})
		resources = append(resources, LiveResource{ID: id, Type: typ, Name: name, Properties: props})
	}

	return resources, nil
}
