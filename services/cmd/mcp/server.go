// SPDX-FileCopyrightText: 2025 Eyad Issa
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"tulip/pkg/db"

	"github.com/charmbracelet/log"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {

	config, err := LoadConfig()
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return
	}

	log.SetLevel(log.DebugLevel)

	// Initialize MongoDB connection using pkg/db
	mongoURI := config.MongoServer()
	mdb := db.ConnectMongo(mongoURI)

	hooks := &server.Hooks{}
	hooks.AddBeforeCallTool(func(ctx context.Context, id any, message *mcp.CallToolRequest) {
		log.Debug("Tool call received", "tool_id", id, "message", message.Method)
	})
	hooks.AddAfterCallTool(func(ctx context.Context, id any, message *mcp.CallToolRequest, result *mcp.CallToolResult) {
		log.Debug("Tool call completed", "tool_id", id, "is_error", result.IsError)
	})

	// Create a new MCP server
	mcpServ := server.NewMCPServer(
		"Demo 🚀",
		"1.0.0",
		server.WithToolCapabilities(false),
	)

	addTools(mcpServ, &mdb)

	// Create HTTP server
	httpServer := server.NewStreamableHTTPServer(mcpServ)

	// Start the stdio server
	log.Info("Starting MCP server on :8080")
	if err := httpServer.Start(":8080"); err != nil {
		log.Fatalf("Failed to start MCP server: %v", err)
	}
}

func addTools(mcpServ *server.MCPServer, database *db.Database) {
	// Add tools to the MCP server
	mcpServ.AddTool(
		mcp.NewTool(
			"getLast10Flows",
			mcp.WithDescription("Fetch the last 10 flows"),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			flows, err := database.GetLastFlows(ctx, 10)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch flows: %v", err)
			}

			log.Debugf("fetched %d flows from the database", len(flows))

			content := bytes.NewBufferString("Last 10 Flows:\n")
			for _, flow := range flows {
				// Format the content for each flow
				fmt.Fprintf(content, "- Flow Details: \n")
				fmt.Fprintf(content, "\tFlow ID: %s\n", flow.Id)
				fmt.Fprintf(content, "\tTimestamp: %d\n", flow.Time)
				fmt.Fprintf(content, "\tSource: %s:%d\n", flow.SrcIp, flow.SrcPort)
				fmt.Fprintf(content, "\tDestination: %s:%d\n", flow.DstIp, flow.DstPort)
				fmt.Fprintf(content, "\tFound flags: %s\n", flow.Flags)
				fmt.Fprintf(content, "\tTags: %s\n", flow.Tags)
			}

			// Return the result
			return mcp.NewToolResultText(content.String()), nil
		},
	)

	mcpServ.AddTool(
		mcp.NewTool(
			"getFlows",
			mcp.WithDescription("Fetch flows based on criteria"),
			mcp.WithNumber("limit", mcp.Required(), mcp.Description("Number of flows to fetch")),
			mcp.WithString("src_ip", mcp.Description("Source IP address to filter flows")),
			mcp.WithString("dst_ip", mcp.Description("Destination IP address to filter flows")),
			mcp.WithNumber("src_port", mcp.Description("Source port to filter flows")),
			mcp.WithNumber("dst_port", mcp.Description("Destination port to filter flows")),
			mcp.WithArray("tags", mcp.Description("Tags to filter flows"), mcp.Items(map[string]any{"type": "number"})),
			mcp.WithString("start_time", mcp.Description("Start time to filter flows (RFC3339 format)")),
			mcp.WithString("end_time", mcp.Description("End time to filter flows (RFC3339 format)")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var err error
			opts := &db.GetFlowsOptions{}

			// Parse the request parameters
			opts.Limit = request.GetInt("limit", 10)
			if opts.Limit >= 5 {
				return mcp.NewToolResultError("Limit must be less than 5"), nil
			}
			if opts.Limit <= 0 {
				return mcp.NewToolResultError("Limit must be greater than 0"), nil
			}

			opts.SrcIp = request.GetString("src_ip", "")
			opts.DstIp = request.GetString("dst_ip", "")

			opts.SrcPort = request.GetInt("src_port", 0)
			opts.DstPort = request.GetInt("dst_port", 0)

			opts.IncludeTags = request.GetStringSlice("tags", []string{})
			opts.FromTime = int64(request.GetInt("start_time", 0))
			opts.ToTime = int64(request.GetInt("end_time", 0))

			flows, err := database.GetFlows(ctx, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch flows: %v", err)
			}

			content := bytes.NewBufferString("Flows:\n")
			for _, flow := range flows {

				fmt.Fprintf(content, "\tFlow ID: %s\n", flow.Id)
				fmt.Fprintf(content, "\tTimestamp: %d\n", flow.Time)
				fmt.Fprintf(content, "\tSource: %s:%d\n", flow.SrcIp, flow.SrcPort)
				fmt.Fprintf(content, "\tDestination: %s:%d\n", flow.DstIp, flow.DstPort)
				fmt.Fprintf(content, "\tFound flags: %s\n", flow.Flags)
				fmt.Fprintf(content, "\tTags: %s\n", flow.Tags)

			}

			return mcp.NewToolResultText(content.String()), nil
		},
	)

	strToClientServer := func(str string) string {
		if str == "c" {
			return "Client to Server"
		} else if str == "s" {
			return "Server to Client"
		} else {
			return "Unknown Direction"
		}
	}

	mcpServ.AddTool(
		mcp.NewTool(
			"getFlow",
			mcp.WithDescription("Fetch a single flow by its ID"),
			mcp.WithString("flow_id", mcp.Required(), mcp.Description("The ID of the flow to fetch")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			flowID := request.GetString("flow_id", "")
			if flowID == "" {
				return mcp.NewToolResultError("flow_id is required"), nil
			}

			flow, err := database.GetFlowByID(ctx, flowID)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch flow: %v", err)
			}
			if flow == nil {
				return mcp.NewToolResultError("Flow not found"), nil
			}

			content := bytes.NewBufferString("")

			fmt.Fprintf(content, "Flow ID: %s\n", flow.Id)
			fmt.Fprintf(content, "Timestamp: %d\n", flow.Time)
			fmt.Fprintf(content, "Source: %s:%d\n", flow.SrcIp, flow.SrcPort)
			fmt.Fprintf(content, "Destination: %s:%d\n", flow.DstIp, flow.DstPort)
			fmt.Fprintf(content, "Found flags: %s\n", strings.Join(flow.Flags, ", "))
			fmt.Fprintf(content, "Tags: %s\n", strings.Join(flow.Tags, ", "))
			fmt.Fprintf(content, "Number of messages: %d\n", len(flow.Flow))
			fmt.Fprintf(content, "\n")

			for i, message := range flow.Flow {
				fmt.Fprintf(content, "--- Message %d ---\n", i+1)
				fmt.Fprintf(content, "Message direction: %s\n", strToClientServer(message.From))
				fmt.Fprintf(content, "Message timestamp: %d\n", message.Time)
				fmt.Fprintf(content, "Message data: ```\n")
				fmt.Fprintf(content, "%s\n", message.Data)
				fmt.Fprintf(content, "```\n")
				fmt.Fprintf(content, "Message data in base64: ```\n")
				fmt.Fprintf(content, "%s\n", message.B64)
				fmt.Fprintf(content, "```\n")
			}

			return mcp.NewToolResultText(content.String()), nil
		},
	)
}
