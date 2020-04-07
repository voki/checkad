# checkad

Checkad is Nagios plugin. It checks for status of user account. It can also check
 accounts status of all members of given group.

## Installation

Compile and install go binary.

```bash
go install checkad
```

## Help

```bash
checkad -h
checkad [command] -h
```

## Example Usage

```bash
checkad disabled -u username
checkad disabled -u username1,username2
checkad expired -g GROUP-NAME -c 7 -w 14 -e "OU=Service Accounts"
checkad locked -g GROUP-NAME -n -v

```
## Config File
Checkad is looking for a checkad.yaml file in several locations:

- Local directory
- Home directory
- /etc/checkad/checkad.yaml
- $GOPATH/checkad

```yaml
host: ldap.example.com:389
insecureSkipVerify: true
startTLS: true
bindDN: user@domain
bindPW: password
userSearch:
  baseDN: DC=example,DC=com
  filter: (objectClass=person)
  nameAttr: sAMAccountName
groupSearch:
  baseDN: DC=example,DC=com
  filter: (objectClass=group)
  userAttr: member
  nameAttr: name
```

