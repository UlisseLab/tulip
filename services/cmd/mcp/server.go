// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"tulip/pkg/db"

	"github.com/lmittmann/tint"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"go.mongodb.org/mongo-driver/bson"
)

func main() {

	// Setup logging (tint handler, assembler style)
	logger := slog.New(tint.NewHandler(os.Stderr, &tint.Options{
		Level:      slog.LevelInfo,
		TimeFormat: "2006-01-02 15:04:05",
	}))
	slog.SetDefault(logger)

	config, err := LoadConfig()
	if err != nil {
		slog.Error("Error loading configuration", slog.Any("err", err))
		return
	}



	// Initialize MongoDB connection using pkg/db
	mongoURI := config.MongoServer()
	mdb, err := db.ConnectMongo(mongoURI)
	if err != nil {
		slog.Error("Failed to connect to MongoDB", slog.Any("err", err))
		return
	}

	hooks := &server.Hooks{}
	hooks.AddBeforeCallTool(func(ctx context.Context, id any, message *mcp.CallToolRequest) {
		slog.Debug("Tool call received", slog.Any("tool_id", id), slog.String("message", message.Method))
	})
	hooks.AddAfterCallTool(func(ctx context.Context, id any, message *mcp.CallToolRequest, result *mcp.CallToolResult) {
		slog.Debug("Tool call completed", slog.Any("tool_id", id), slog.Bool("is_error", result.IsError))
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
	slog.Info("Starting MCP server on :8080")
	if err := httpServer.Start(":8080"); err != nil {
		slog.Error("Failed to start MCP server", slog.Any("err", err))
	}
}

func strToClientServer(str string) string {
	switch str {
	case "c":
		return "Client to Server"
	case "s":
		return "Server to Client"
	default:
		return "Unknown Direction"
	}
}

func addTools(mcpServ *server.MCPServer, database *db.MongoDatabase) {

	// List Tags Tool
	mcpServ.AddTool(
		mcp.NewTool(
			"listTags",
			mcp.WithDescription("List all unique tags used in flows"),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			tags, err := database.GetTagList()
			if err != nil {
				return nil, fmt.Errorf("failed to list tags: %v", err)
			}
			return mcp.NewToolResultText(fmt.Sprintf("Tags: %s", strings.Join(tags, ", "))), nil
		},
	)

	// Flow Count Tool
	mcpServ.AddTool(
		mcp.NewTool(
			"flowCount",
			mcp.WithDescription("Count the number of flows matching optional criteria"),
			mcp.WithString("src_ip", mcp.Description("Source IP address to filter flows")),
			mcp.WithString("dst_ip", mcp.Description("Destination IP address to filter flows")),
			mcp.WithNumber("src_port", mcp.Description("Source port to filter flows")),
			mcp.WithNumber("dst_port", mcp.Description("Destination port to filter flows")),
			mcp.WithArray("tags", mcp.Description("Tags to filter flows"), mcp.Items(map[string]any{"type": "string"})),
			mcp.WithString("start_time", mcp.Description("Start time to filter flows (RFC3339 format)")),
			mcp.WithString("end_time", mcp.Description("End time to filter flows (RFC3339 format)")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			// Build filters similar to GetFlowList
			filters := bson.D{}
			if v := request.GetString("src_ip", ""); v != "" {
				filters = append(filters, bson.E{Key: "src_ip", Value: v})
			}
			if v := request.GetString("dst_ip", ""); v != "" {
				filters = append(filters, bson.E{Key: "dst_ip", Value: v})
			}
			if v := request.GetInt("src_port", 0); v != 0 {
				filters = append(filters, bson.E{Key: "src_port", Value: v})
			}
			if v := request.GetInt("dst_port", 0); v != 0 {
				filters = append(filters, bson.E{Key: "dst_port", Value: v})
			}
			if tags := request.GetStringSlice("tags", []string{}); len(tags) > 0 {
				filters = append(filters, bson.E{Key: "tags", Value: map[string]any{"$all": tags}})
			}
			// Optionally add time range filtering if your schema supports it

			count, err := database.CountFlows(filters)
			if err != nil {
				return nil, fmt.Errorf("failed to count flows: %v", err)
			}
			return mcp.NewToolResultText(fmt.Sprintf("Total flows: %d", count)), nil
		},
	)

	mcpServ.AddTool(
		mcp.NewTool(
			"getFlows",

			mcp.WithTitleAnnotation("Get Flows"),
			mcp.WithDescription("Fetch flows based on criteria, including source/destination IPs, "+
				"ports, tags, and time range"),

			mcp.WithNumber("limit", mcp.Required(), mcp.Description("Number of flows to fetch")),
			mcp.WithString("src_ip", mcp.Description("Source IP address to filter flows")),
			mcp.WithString("dst_ip", mcp.Description("Destination IP address to filter flows")),
			mcp.WithNumber("src_port", mcp.Description("Source port to filter flows")),
			mcp.WithNumber("dst_port", mcp.Description("Destination port to filter flows")),
			mcp.WithArray("tags", mcp.Description("Tags to filter flows"), mcp.Items(map[string]any{"type": "number"})),
			mcp.WithString("start_time", mcp.Description("Start time to filter flows (RFC3339 format)")),
			mcp.WithString("end_time", mcp.Description("End time to filter flows (RFC3339 format)")),
			mcp.WithString("flow_data", mcp.Description("Flow data to filter flows, you can insert any string you want to search for in the flow data")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			opts := &db.GetFlowsOptions{}

			// Parse the request parameters
			opts.Limit = request.GetInt("limit", 0)
			if opts.Limit < 0 {
				return mcp.NewToolResultError("Limit must be a non-negative integer"), nil
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

			content := bytes.NewBufferString("")
			fmt.Fprintf(content, "\nTotal flows found: %d\n", len(flows))

			fmt.Fprintf(content, "Flows:\n")
			for _, flow := range flows {

				fmt.Fprintf(content, "\tFlow ID: %s\n", flow.Id)
				fmt.Fprintf(content, "\tTimestamp: %d\n", flow.Time)
				fmt.Fprintf(content, "\tSource: %s:%d\n", flow.SrcIp, flow.SrcPort)
				fmt.Fprintf(content, "\tDestination: %s:%d\n", flow.DstIp, flow.DstPort)
				fmt.Fprintf(content, "\tFound flags: %s\n", flow.Flags)
				fmt.Fprintf(content, "\tTags: %s\n", flow.Tags)

			}

			fmt.Fprintf(content, "\nYou can use the `getFlow` tool to fetch more details and all the "+
				"captured messages for a specific flow by its ID.\n")

			return mcp.NewToolResultText(content.String()), nil
		},
	)

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
