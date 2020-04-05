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
	"strings"
)

//Config struct to unmarshal yaml config to.
type Config struct {
	Host               string `yaml:"host"`
	InsecureSkipVerify bool   `yaml:"insecureSkipVerify"`
	StartTLS           bool   `yaml:"startTLS"`
	BindDN             string `yaml:"bindDN"`
	BindPW             string `yaml:"bindPW"`
	UserSearch         struct {
		BaseDN   string `yaml:"baseDN"`
		Filter   string `yaml:"filter"`
		NameAttr string `yaml:"username"`
	} `yaml:"userSearch"`
	GroupSearch struct {
		BaseDN    string `yaml:"baseDN"`
		Filter    string `yaml:"filter"`
		UserAttr  string `yaml:"userAttr"`
		GroupAttr string `yaml:"groupAttr"`
		NameAttr  string `yaml:"nameAttr"`
	} `yaml:"groupSearch"`
}

//Validate config file
func (c Config) Validate() error {

	host := c.Host
	bindDN := c.BindDN
	bindPW := c.BindPW
	userSearchBaseDN := c.UserSearch.BaseDN
	userSearchFilter := c.UserSearch.Filter
	userSearchNameAttr := c.UserSearch.NameAttr
	groupSearchBaseDN := c.GroupSearch.BaseDN
	groupSearchFilter := c.GroupSearch.Filter
	groupSearchUserAttr := c.GroupSearch.UserAttr
	groupSearchNameAttr := c.GroupSearch.NameAttr

	// Fast checks. Perform these first for a more responsive CLI.
	checks := []struct {
		bad    bool
		errMsg string
	}{
		{host == "", "no ldap host specified!"},
		{bindDN == "", "bindDN not provided!"},
		{bindPW == "", "bindPW not provided!"},
		{userSearchBaseDN == "", "userSearch baseDN value not provided!"},
		{userSearchFilter == "", "userSearch filter value not provided!"},
		{userSearchNameAttr == "", "userSearch nameAttr value not provided!"},
		{groupSearchBaseDN == "", "groupSearch baseDN value not provided!"},
		{groupSearchFilter == "", "groupSearch filter value not provided!"},
		{groupSearchUserAttr == "", "groupSearch userAttr value not provided!"},
		{groupSearchNameAttr == "", "groupSearch nameAttr value not provided!"},
	}

	var checkErrors []string

	for _, check := range checks {
		if check.bad {
			checkErrors = append(checkErrors, check.errMsg)
		}
	}
	if len(checkErrors) != 0 {
		return fmt.Errorf("Invalid Config:\n\t- %s", strings.Join(checkErrors, "\n\t- "))
	}
	return nil
}
