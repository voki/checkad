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
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const (
	ScopeBaseObject   = 0
	ScopeSingleLevel  = 1
	ScopeWholeSubtree = 2
)

const (
	NeverDerefAliases   = 0
	DerefInSearching    = 1
	DerefFindingBaseObj = 2
	DerefAlways         = 3
)

// Result stores user account status along with user, email, userAccountControl, accountExpires information
type Result struct {
	user     string
	email    string
	uacCode  string
	expTime  string
	lockTime string
	exitCode int
}

//ldapClient binds and returns connection
func ldapClient(c Config) *ldap.Conn {
	url := fmt.Sprintf("ldap://%s", c.Host)
	client, err := ldap.DialURL(url)
	if err != nil {
		log.Fatal(err)
	}

	if c.StartTLS {
		if verbose {
			log.Println("--> Starting TLS")
		}

		err = client.StartTLS(&tls.Config{InsecureSkipVerify: c.InsecureSkipVerify})
		if err != nil {
			log.Fatal(err)
		}
	}

	err = client.Bind(c.BindDN, c.BindPW)
	if err != nil {
		log.Fatal(err)
	}

	return client
}

//ldapCheckUser searches for user and returns account attributes
func ldapCheckUser(conn *ldap.Conn, c Config, searchByAttr string, userName string) []Result {

	var res = []Result{}
	var searchFilter string
	var baseDN string
	var scope = ScopeWholeSubtree
	retCode := 0
	baseDN = c.UserSearch.BaseDN

	if verbose {
		log.Printf("--> Checking if [%s] user account is disabled...\n", userName)
	}

	if searchByAttr == "CN" || searchByAttr == "cn" {
		searchFilter = fmt.Sprintf("(&%s(%s))", c.UserSearch.Filter, userName)

	} else if searchByAttr == "group" {
		searchFilter = "(&(objectClass=*))"
		baseDN = userName
		scope = ScopeBaseObject
	} else {
		searchFilter = fmt.Sprintf("(&%s(%s=%s))", c.UserSearch.Filter, searchByAttr, userName)

	}

	if verbose {
		log.Printf("--> Using search filter: %s", searchFilter)
	}

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		scope, NeverDerefAliases, 0, 0, false,
		searchFilter,
		[]string{"dn", c.UserSearch.NameAttr, "userPrincipalName", "displayName", "userAccountControl", "accountExpires", "lockoutTime"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	if len(sr.Entries) == 0 {
		var user = Result{}
		user.user = userName
		user.exitCode = 5
		res = append(res, user)
	} else {

		for _, entry := range sr.Entries {
			var user = Result{}
			user.user = entry.GetAttributeValue(c.UserSearch.NameAttr)
			user.email = entry.GetAttributeValue("userPrincipalName")
			user.uacCode = entry.GetAttributeValue("userAccountControl")
			user.expTime = entry.GetAttributeValue("accountExpires")
			user.lockTime = entry.GetAttributeValue("lockoutTime")

			if verbose {
				log.Printf("--> Found user: [%s]\n", entry.GetAttributeValue("displayName"))
				entry.PrettyPrint(24)
			}

			adUacCode := entry.GetAttributeValue("userAccountControl")

			if adUacCode == "512" || adUacCode == "66048" {
				retCode = 0
			} else if adUacCode == "514" {
				retCode = 2
			} else {
				retCode = 3
			}
			user.exitCode = retCode
			res = append(res, user)
		}

	}

	return res
}

//ldapCheckGroup checks all members of the group, it calls ldapCheckUser to check attributes of single user.
func ldapCheckGroup(conn *ldap.Conn, c Config, groupName string) []Result {

	var res = []Result{}
	var members []string
	var excluded []string
	var filterMemberOf string
	var filter string
	var groupDN string

	if verbose {
		log.Printf("--> Checking if %s members accounts are disabled...\n", groupName)
	}

	groupDN = getGroupDN(conn, c, groupName)

	if verbose {
		log.Printf("--> Found group: %s\n", groupDN)
	}

	if nested {
		filterMemberOf = fmt.Sprintf("memberOf:1.2.840.113556.1.4.1941:=%s", groupDN)
	} else {
		filterMemberOf = fmt.Sprintf("memberOf=%s", groupDN)
	}

	filter = fmt.Sprintf("(&(objectClass=user)(%s))", filterMemberOf)

	if verbose {
		log.Printf("--> Using search filter: %s", filter)
	}

	searchRequest := ldap.NewSearchRequest(
		c.UserSearch.BaseDN,
		ScopeWholeSubtree, NeverDerefAliases, 0, 0, false, filter, []string{"dn"}, nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	if verbose {
		log.Printf("--> Found %d users...", len(sr.Entries))
	}

	for _, entry := range sr.Entries {
		if verbose {
			log.Printf("--> %s", entry.DN)
		}
		if exclude != "" {
			if strings.Contains(entry.DN, exclude) {
				excluded = append(excluded, entry.DN)
			} else {
				members = append(members, entry.DN)
			}
		} else {
			members = append(members, entry.DN)
		}
	}

	if verbose {
		for _, entry := range excluded {
			log.Printf("--> Excluded user: %s", entry)
		}
	}

	for _, member := range members {
		res = append(res, ldapCheckUser(conn, c, "group", member)...)
	}

	return res
}

//getGroupDD returns full DN of group
func getGroupDN(conn *ldap.Conn, c Config, groupName string) string {
	var groupDN string

	searchGroupDN := ldap.NewSearchRequest(
		c.UserSearch.BaseDN,
		ScopeWholeSubtree, NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&%s(%s=%s))", c.GroupSearch.Filter, c.GroupSearch.NameAttr, groupName),
		[]string{"dn"},
		nil,
	)

	sgDN, err := conn.Search(searchGroupDN)
	if err != nil {
		log.Fatal(err)
	}

	if len(sgDN.Entries) != 1 {
		fmt.Println("Query returned error!")
	} else {
		groupDN = strings.Replace(sgDN.Entries[0].DN, "\\", "", -1)
	}

	return groupDN
}

//checkResultsDisabled checks if any of the user(s) is in disabled state
func checkResultsDisabled(r []Result) {

	var disabled string
	var unknown string
	var notFound string

	for _, user := range r {
		switch user.exitCode {
		case 0:
		case 2:
			disabled = disabled + fmt.Sprintf("[%s(%s)] ", user.email, user.user)
		case 3:
			unknown = unknown + fmt.Sprintf("[%s(%s)(UAC:%s)] ", user.email, user.user, user.uacCode)
		case 5:
			notFound = notFound + fmt.Sprintf("[%s] ", user.user)
		}
	}

	if disabled != "" {
		fmt.Printf("CRITICAL: Disabled account(s) - %s\n", disabled)
		os.Exit(2)
	}

	if unknown != "" {
		fmt.Printf("UNKNOWN: Account(s) in unknown state - %s\n", unknown)
		os.Exit(3)
	}

	if notFound != "" {
		fmt.Printf("UNKNOWN: Account(s) not found - %s\n", notFound)
		os.Exit(3)
	}

	fmt.Printf("OK: No disabled account(s)\n")
	os.Exit(0)

}

func checkResultsExpired(r []Result, warning int, critical int) {
	var warningUsers string
	var criticalUsers string

	for _, user := range r {
		daysValid := getDaysFromNow(user.expTime)

		if daysValid > critical && daysValid <= warning {
			warningUsers = warningUsers + fmt.Sprintf("[%s (%s) DTE: %d] ", user.email, user.user, daysValid)
		} else if daysValid <= critical {
			criticalUsers = criticalUsers + fmt.Sprintf("[%s (%s) DTE: %d] ", user.email, user.user, daysValid)
		}
	}
	if warningUsers != "" && criticalUsers != "" {
		fmt.Printf("CRITICAL: Account(s) about to expire - %s | Accounts in WARNING state - %s\n", criticalUsers, warningUsers)
		os.Exit(2)
	}

	if criticalUsers != "" {
		fmt.Printf("CRITICAL: Account(s) about to expire - %s\n", criticalUsers)
		os.Exit(2)
	}

	if warningUsers != "" {
		fmt.Printf("WARNING: Account(s) about to expire - %s\n", warningUsers)
		os.Exit(1)
	}

	fmt.Printf("OK: No expiring account(s)\n")
	os.Exit(0)

}

func checkResultsLocked(r []Result) {
	var lockedUsers string

	for _, user := range r {
		if user.lockTime != "0" && user.lockTime != "" {
			lockedUsers = lockedUsers + fmt.Sprintf("[%s (%s)] ", user.email, user.user)
		}
	}

	if lockedUsers != "" {
		fmt.Printf("CRITICAL: Locked account(s) - %s\n", lockedUsers)
		os.Exit(2)
	} else {
		fmt.Printf("OK: No locked account(s)\n")
		os.Exit(0)
	}
}

func getDaysFromNow(accExp string) int {
	var epochNow int64
	var epochAccExp int64

	ae, err := strconv.ParseInt(accExp, 10, 64)
	if err != nil {
		panic(err)
	}

	epochNow = time.Now().Unix()
	epochAccExp = ((ae / 10000000) - 11644473600)
	return int((epochAccExp - epochNow) / 86400)
}
