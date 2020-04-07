/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"github.com/spf13/cobra"
)

// lockedCmd represents the locked command
var lockedCmd = &cobra.Command{
	Use:   "locked",
	Short: "Check if user(s) account(s) is(are) locked",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if len(users) > 0 {
			client := ldapClient(config)
			for _, user := range users {
				result = append(result, ldapCheckUser(client, config, config.UserSearch.NameAttr, user)...)
			}
			client.Close()
			if len(result) > 0 {
				checkResultsLocked(result)
			}
		}

		if groupName != "" {
			client := ldapClient(config)
			result := ldapCheckGroup(client, config, groupName)
			client.Close()
			if len(result) > 0 {
				checkResultsLocked(result)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(lockedCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// lockedCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:

}
