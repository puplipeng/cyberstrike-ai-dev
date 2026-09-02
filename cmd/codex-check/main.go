package main

import (
	"context"
	"cyberstrike-ai/internal/codexbridge"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	infer := flag.Bool("infer", false, "Send one minimal model request using the current Codex ChatGPT account")
	chosen := flag.String("model", "", "Model to verify; empty selects Codex's default")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	status, err := codexbridge.Check(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if !*infer {
		json.NewEncoder(os.Stdout).Encode(status)
		return
	}
	name := *chosen
	if name == "" {
		for _, m := range status.Models {
			if m.IsDefault {
				name = m.Model
				break
			}
		}
	}
	if name == "" {
		fmt.Fprintln(os.Stderr, "No default model available")
		os.Exit(1)
	}
	c, err := codexbridge.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer c.Close()
	result, err := c.Run(ctx, codexbridge.Request{Model: name, Instructions: "Return exactly CODEX_ACCOUNT_OK. Do not use tools.", Input: "Confirm connectivity."}, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"account_type": "chatgpt", "model": name, "reply": result.Text, "input_tokens": result.InputTokens, "output_tokens": result.OutputTokens})
}
