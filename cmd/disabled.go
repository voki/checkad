/*
Copyright © 2020 Kamil Wokitajtis <wokitajtis@gmail.com>

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

// disabledCmd represents the disabled command
var disabledCmd = &cobra.Command{
	Use:   "disabled ",
	Short: "Check if user(s) account(s) is(are) disabled",
	Long:  ``,
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {

		if len(users) > 0 {
			client := ldapClient(config)
			for _, user := range users {
				result = append(result, ldapCheckUser(client, config, config.UserSearch.NameAttr, user)...)
			}
			client.Close()
			if len(result) > 0 {
				checkResultsDisabled(result)
			}
		}

		if groupName != "" {
			client := ldapClient(config)
			result := ldapCheckGroup(client, config, groupName)
			client.Close()
			if len(result) > 0 {
				checkResultsDisabled(result)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(disabledCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// disabledCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:

}
