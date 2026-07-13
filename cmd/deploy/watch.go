package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

/*
	deploy watch [tag]

	Blocks until every pipeline in the tag's semaphore workflow is done, printing
	pipeline states as they change, then prints per-pipeline results.

	Defaults to the most recent test tag when no tag is given.

	Exit codes: 0 = every pipeline passed, 1 = at least one pipeline failed,
	2 = workflow not found or timed out.

	This exists so agents and scripts have ONE reliable way to wait on a CI run,
	instead of hand-rolling sem polling. sem get ppl output is indented yaml, so a
	naive grep for ^state: silently never matches and the poll loop spins forever.
*/

const watchPollTime = 30 * time.Second
const watchFindTime = 5 * time.Minute
const watchTimeoutTime = 90 * time.Minute

type watchPipeline struct {
	id    string
	name  string
	state string
}

func isUUID(value string) bool {
	return len(value) == 36 && strings.Count(value, "-") == 4
}

// parse the pipeline table from "sem get wf <workflow-id>". pipeline names contain
// spaces, so split by field position: id | name... | creation date | creation time | state

func parseWatchPipelines(output string) []watchPipeline {
	pipelines := []watchPipeline{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || !isUUID(fields[0]) {
			continue
		}
		pipeline := watchPipeline{}
		pipeline.id = fields[0]
		pipeline.state = fields[len(fields)-1]
		pipeline.name = strings.Join(fields[1:len(fields)-3], " ")
		pipelines = append(pipelines, pipeline)
	}
	return pipelines
}

// the first result: line in "sem get ppl <pipeline-id>" is the pipeline's own result
// (block results follow it at the same indent, so order matters here)

func getWatchPipelineResult(pipelineId string) string {
	output := BashQuiet(fmt.Sprintf("sem get ppl %s", pipelineId))
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "result:") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, "result:"))
		}
	}
	return "unknown"
}

func findWatchWorkflow(label string) string {
	output := BashQuiet("sem get wf -p next")
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && isUUID(fields[0]) && fields[len(fields)-1] == label {
			return fields[0]
		}
	}
	return ""
}

func watch(args []string) {

	tag := ""
	if len(args) >= 1 {
		tag = args[0]
	} else {
		tag = strings.TrimSpace(BashQuiet("git tag --list --sort=-version:refname \"test-*\" | head -n 1"))
		if tag == "" {
			fmt.Printf("error: no test tags found\n")
			os.Exit(2)
		}
	}

	fmt.Printf("\nWatching %s\n\n", tag)

	// the workflow takes a few seconds to appear on semaphore after the tag is pushed

	workflowId := ""
	findDeadline := time.Now().Add(watchFindTime)
	for {
		workflowId = findWatchWorkflow("refs/tags/" + tag)
		if workflowId != "" {
			break
		}
		if time.Now().After(findDeadline) {
			fmt.Printf("error: could not find workflow for %s\n\n", tag)
			os.Exit(2)
		}
		time.Sleep(10 * time.Second)
	}

	// poll until every pipeline is done on two consecutive polls with the same pipeline
	// count. the second poll is load-bearing: the build pipeline finishing is what spawns
	// the promoted pipelines (sdk tests, functional tests, happy path), so a single
	// "all done" observation can land in the gap before the promotions appear.

	timeoutDeadline := time.Now().Add(watchTimeoutTime)

	var pipelines []watchPipeline

	lastStatus := ""
	confirmedCount := -1

	for {

		if time.Now().After(timeoutDeadline) {
			fmt.Printf("error: timed out waiting for %s\n\n", tag)
			os.Exit(2)
		}

		pipelines = parseWatchPipelines(BashQuiet(fmt.Sprintf("sem get wf %s", workflowId)))

		if len(pipelines) > 0 {

			allDone := true
			status := ""
			for i := range pipelines {
				status += fmt.Sprintf("%s [%s]  ", pipelines[i].name, pipelines[i].state)
				if pipelines[i].state != "DONE" {
					allDone = false
				}
			}

			if status != lastStatus {
				fmt.Printf("%s\n", strings.TrimSpace(status))
				lastStatus = status
			}

			if allDone {
				if confirmedCount == len(pipelines) {
					break
				}
				confirmedCount = len(pipelines)
			} else {
				confirmedCount = -1
			}
		}

		time.Sleep(watchPollTime)
	}

	// print per-pipeline results

	fmt.Printf("\n")

	allPassed := true
	for i := range pipelines {
		result := getWatchPipelineResult(pipelines[i].id)
		if result != "passed" {
			allPassed = false
		}
		fmt.Printf("    %-20s %s\n", pipelines[i].name, result)
	}

	fmt.Printf("\n")

	if !allPassed {
		os.Exit(1)
	}
}
