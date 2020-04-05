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
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

//VERSION is build generated
var VERSION string
var cfgFile string
var config Config
var verbose bool
var nested bool
var userName string
var groupName string
var exclude string
var result []Result

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "checkad",
	Short: "A brief description of your application",
	Long: `
Checkad is a Nagios plugin, it allows to check if account is in disabled/expired/locked state.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//Run: func(cmd *cobra.Command, args []string) {},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(version string) {
	VERSION = version
	if err := rootCmd.Execute(); err != nil {

	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/checkad.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.

	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose mode")
	rootCmd.PersistentFlags().BoolVarP(&nested, "nested", "n", false, "Search nested groups also")
	rootCmd.PersistentFlags().StringVarP(&userName, "user", "u", "", "Check single user account(s)")
	rootCmd.PersistentFlags().StringVarP(&groupName, "group", "g", "", "Check all group members accounts")
	rootCmd.PersistentFlags().StringVarP(&exclude, "exclude", "e", "", "Exclude OU, eg. OU=Service Accounts")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".checkad" (without extension).
		viper.SetConfigName("checkad")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(home)               // home path
		viper.AddConfigPath("/etc/checkad/")    // path to look for the config file in
		viper.AddConfigPath("$GOPATH/checkad/") // call multiple times to add many search paths
		viper.AddConfigPath(".")                // optionally look for config in the working directory
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {

		if verbose {
			log.Println("--> Using config file:", viper.ConfigFileUsed())
		}

		err := viper.Unmarshal(&config)
		if err != nil {
			fmt.Printf("unable to decode into struct, %v\n", err)
		}

		if err := config.Validate(); err != nil {
			fmt.Println(err)
			os.Exit(2)
		}

	} else {
		fmt.Println("Config file not found!")
		os.Exit(2)
	}
}
