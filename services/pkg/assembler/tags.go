// SPDX-FileCopyrightText: 2022 Rick de Jager <rickdejager99@gmail.com>
// SPDX-FileCopyrightText: 2023 - 2024 gfelber <34159565+gfelber@users.noreply.github.com>
// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package assembler

import (
	"regexp"
	"tulip/pkg/db"

	"golang.org/x/exp/slices"
)

// Apply flag in/flag out tags to the entire flow.
// This assumes the `Data` part of the flowItem is already pre-processed, s.t.
// we can run regex tags over the payload directly
// also add the matched flags to the FlowItem
func ApplyFlagTags(flow *db.FlowEntry, flagRegex regexp.Regexp) {
	for idx := 0; idx < len(flow.Flow); idx++ {
		flowItem := &flow.Flow[idx]
		matches := flagRegex.FindAllStringSubmatch(flowItem.Data, -1)
		if len(matches) > 0 {
			var tag string
			if flowItem.From == "c" {
				tag = "flag-in"
			} else {
				tag = "flag-out"
			}

			// Add the flag if it doesn't already exist
			for _, match := range matches {
				var flag string
				flag = match[0]
				if !slices.Contains(flow.Flags, flag) {
					flow.Flags = append(flow.Flags, flag)
				}
			}

			// Add the tag if it doesn't already exist
			if !slices.Contains(flow.Tags, tag) {
				flow.Tags = append(flow.Tags, tag)
			}
		}
	}
}
