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

var daysWarning int
var daysCritical int

// expiredCmd represents the expired command
var expiredCmd = &cobra.Command{
	Use:   "expired",
	Short: "Check if user(s) account(s) expired",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if len(users) > 0 {
			client := ldapClient(config)
			for _, user := range users {
				result = append(result, ldapCheckUser(client, config, config.UserSearch.NameAttr, user)...)
			}
			client.Close()
			if len(result) > 0 {
				checkResultsExpired(result, daysWarning, daysCritical)
			}
		}

		if groupName != "" {
			client := ldapClient(config)
			result := ldapCheckGroup(client, config, groupName)
			client.Close()
			if len(result) > 0 {
				checkResultsExpired(result, daysWarning, daysCritical)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(expiredCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// expiredCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// expiredCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	expiredCmd.Flags().IntVarP(&daysWarning, "warning", "w", 14, "Trigger warning state x days before account expiry")
	expiredCmd.Flags().IntVarP(&daysCritical, "critical", "c", 7, "Trigger critical state x days before account expiry")
}
