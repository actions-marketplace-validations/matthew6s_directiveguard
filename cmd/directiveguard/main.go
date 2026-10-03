package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/matthew6s/directiveguard/internal/report"
	"github.com/matthew6s/directiveguard/internal/scanner"
	"github.com/matthew6s/directiveguard/internal/upload"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("directiveguard", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "text", "output format: text, json, or sarif")
	failOn := flags.String("fail-on", "high", "exit 1 at this severity: low, medium, high, or none")
	showVersion := flags.Bool("version", false, "print version")
	uploadURL := flags.String("upload", "", "upload results to a DirectiveGuard Cloud URL")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: directiveguard [options] [path]")
		fmt.Fprintln(stderr, "Scan a repository for unsafe AI-agent configuration.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "directiveguard %s\n", buildVersion())
		return 0
	}
	if flags.NArg() > 1 {
		fmt.Fprintln(stderr, "directiveguard: expected at most one path")
		return 2
	}
	root := "."
	if flags.NArg() == 1 {
		root = flags.Arg(0)
	}
	threshold, err := scanner.ParseThreshold(*failOn)
	if err != nil {
		fmt.Fprintf(stderr, "directiveguard: %v\n", err)
		return 2
	}
	result, err := scanner.Scan(root)
	if err != nil {
		fmt.Fprintf(stderr, "directiveguard: %v\n", err)
		return 2
	}
	if err := report.Write(stdout, *format, result); err != nil {
		fmt.Fprintf(stderr, "directiveguard: %v\n", err)
		return 2
	}
	if *uploadURL != "" {
		apiKey := os.Getenv("DIRECTIVEGUARD_API_KEY")
		if apiKey == "" {
			apiKey = os.Getenv("INPUT_API_KEY")
		}
		if err := upload.Send(context.Background(), *uploadURL, apiKey, result, upload.Metadata{CommitSHA: os.Getenv("GITHUB_SHA"), Branch: os.Getenv("GITHUB_REF_NAME")}); err != nil {
			fmt.Fprintf(stderr, "directiveguard: %v\n", err)
			return 2
		}
	}
	if result.Fails(threshold) {
		return 1
	}
	return 0
}

func buildVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}
