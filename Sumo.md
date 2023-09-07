# Sumo-fu

Using `IsEmpty` and geo-IP lookup:
```text
(_sourceCategory=wce/prod/auth0 OR _sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com)
| json field=_raw "data.ip"
| if (IsEmpty(ip), %data.ip, ip) as ip_address
| json field=_raw "data.type"
| where %type = "s" or %data.type = "s"
| lookup latitude, longitude, city, country_name
    from geo://location on ip=ip_address
//| json field=_raw "user_name"
//| json field=_raw "date"
| count by country_name
| order by _count
```

Note the use of the tuples here—the first is the connection name, the second is a label to apply to the connection.

```text
(_sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com)
| json field=_raw "strategy"
| json field=_raw "strategy_type"
| json field=_raw "connection"
| json field=_raw "connection_id"
| if (connection = "auth0", "Auth0 Database User", %connection) as ignore
| if (connection = "empire-life", "Employee G Suite Login", %connection) as cxn
| if (connection = "RBC", "RBC SSO", %connection) as cxn
| timeslice by 1d
| count by _timeslice, cxn
| transpose row _timeslice column cxn
```

```text
(_sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com or _sourceCategory=wce/prod/auth0)
| json field=_raw "type" | where %type = "seccft"
| json field=_raw "audience" | where !(%audience = "https://sso.empire-prod.auth0.com/api/v2/")
| json field=_raw "client_name"
| timeslice by 1w
| count by _timeslice
//| count by _timeslice, %client_name
//| transpose row _timeslice column %client_name
```

Checks for instances where Bot Detection would have requested a CAPTCHA:
```text
(_sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com)
| json field=_raw "type" | where %type = "pla"
| json field=_raw "details.requiresVerification" | where %details.requiresVerification = "true" 
| timeslice by 1d
| count by _timeslice
```

```text
_sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com
| json field=_raw "data.details.requiresVerification" | where %"data.details.requiresVerification" = "true"
| where %"data.type" = "pla"
| timeslice 1h | count by _timeslice
```

Check for breached password:

```text
(_sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com)
| json field=_raw "type" | where %type = "pwd_leak"
| json field=_raw "user_name" as email_address
| json field=_raw "ip" as ip_address
| lookup latitude, longitude, city, country_name
  from geo://location on ip=ip_address
| count by email_address, ip_address, latitude, longitude, city, country_name
| order by email_address
```

Client activity count:

```text
_sourceCategory=iam/auth0/tenants/dev.empire-staging.auth0.com
| json field=_raw "data.client_name"
| json field=_raw "data.client_id"
| count by %"data.client_name",%"data.client_id"
| order by _count
```

Looking for webtask timeouts:

```text
_sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com
| where %data.description = "Request to Webtask exceeded allowed execution time" or %description = "Request to Webtask exceeded allowed execution time"
| timeslice 1d
| count by _timeslice
```

Stale bookmarks:

```text
_sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com and "bookmark"
| timeslice 1w
//| count by %data.type,%data.description
//| order by _count
| count by _timeslice
| order by _timeslice
//| transpose row _timeslice column %type
```

Some wonky error:

```text
_sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com AND "Invalid response code from the auth0-sandbox"
| json field=_raw "description"
| timeslice 1d
| count by _timeslice, %description
| order by _count
| transpose row _timeslice column %description
```

Deprecation notifications:

```text
_sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com and "DDn1OxwyBKqgom0X0j3b4wod2q03SeHo"
| json field=_raw "data.type" | where %data.type matches "f*"
//| count by %data.type,%data.description,%data.client_id
//| json field=_raw "data.type" | where %data.type = "depnote"
//| count by %data.client_id, %data.client_name
//| order by _count
```

Sendgrid logs:

```text
_source="Sendgrid Email Event Notifications"
//| json field=_raw "event"
//| json field=_raw "sg_template_name"
//| json field=_raw "empireID"
//| count by %empireID
| timeslice 1h
| count by _timeslice
| order by _timeslice
```

Sendgrid:

```text
_sourceCategory=sendgrid/notify
| parse regex "\"event\":\"(?<event_type>.*?)\"" multi
| count by event_type
| sort by _count
```

```text
_sourceCategory=sendgrid/notify
| parse regex "\"event\":\"(?<event_type>.*?)\"" multi
| count by event_type
| sort by _count
```

Geo-IP:

```text
_sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com
| where %"data.type" in ("s")
| lookup latitude, longitude, city, country_name
    from geo://location on ip=%"data.ip"
| where country_name not in ("Canada","United States")
| timeslice 1d
| count by _timeslice,country_name
| transpose row _timeslice column country_name
```

Hunting for specific user_id values:

```text
_sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com
| json field=_raw "data.user_id"
| json field=_raw "data.details.body.email"
| json field=_raw "data.user_name"
| json field=_raw "data.ip"
| json field=_raw "data.client_name"
| json field=_raw "data.client_id"
| where %"data.type" = "ss"
| where %"data.user_id" in ("comma","separated","list","of","user_ids")
| lookup latitude, longitude, city, country_name
    from geo://location on ip=%"data.ip"
| count by latitude,longitude
//| timeslice 1d
//| count by _timeslice
```

Excluding specific usernames:

```text
_sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com
| json field=_raw "data.user_id"
| json field=_raw "data.user_name"
| where %"data.type" = "s"
| where %"data.user_name" not in ("user1","user2","user3")
| count by %"data.user_name"
| where _count > 5
| order by _count
```

Use of count_distinct to get unique logins per user per week (Weekly Active Users):

```text
_sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com
| json field=_raw "data.user_id"
| json field=_raw "data.type" | where %"data.type" = "s"
| timeslice 1w | count_distinct(%"data.user_id") group by _timeslice
| order by _timeslice
```

Breached creds report:

```text
_sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com
| json field=_raw "data.date"
| json field=_raw "data.client_id"
| json field=_raw "data.ip"
| json field=_raw "data.type" | where %"data.type" = "pwd_leak"
| json field=_raw "data.user_name"
| lookup latitude, longitude, city, country_name
    from geo://location on ip=%"data.ip"
| count by %"data.user_name", %"data.date", %"data.client_id", country_name, city
| order by _count
```

Failed logins:

```text
_sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com
| json field=_raw "data.type" | where %"data.type" in ("f","fu","fp")
| timeslice 1h | count by _timeslice
|order by _timeslice
```

Logs by source category, all sources:

```text
* | count by _sourceCategory | sort by _count
```

NULL EGP Username field:

```text
_sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com
| json field=_raw "data.type" | where %"data.type" = "sapi"
| json field=_raw "data.details.request.body.app_metadata.applications.egp.username"
| where isNull(%"data.details.request.body.app_metadata.applications.egp.username")
```

Cloudflare WAF events:

```text
_sourceCategory=cloudflare
| json field=_raw "WAFAction" | where %WAFAction != "unknown" 
| json field=_raw "FirewallMatchesRuleIDs" as all_rule_ids
| parse regex field=all_rule_ids "(?<rule>\w+)" multi
| count by rule
| order by _count
```

Report on all non-success logs types with table lookup:

```text
_sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com
| json field=_raw "type" as auth0_log_event_code
| where !(auth0_log_event_code matches "s*")
| lookup event_type from https://raw.githubusercontent.com/dmark/auth0-cli-utilities/master/auth0_log_event_table.csv on auth0_log_event_code=event_code
| lookup event_description from https://raw.githubusercontent.com/dmark/auth0-cli-utilities/master/auth0_log_event_table.csv on auth0_log_event_code=event_code
| json field=_raw "description"
| count by auth0_log_event_code, event_type, event_description, description
| order by _count
```

Password change fail:success ratio:

```text
// fcp, fcpr, scp, scpr
(_sourceCategory=wce/prod/auth0 OR _sourceCategory=auth0/prod)
//| json field=_raw "type" | where %type = "scp" or %type = "fcp"
| json field=_raw "type" | where %type = "scp" or %type = "fcp"
| if(%type matches "scp", 1, 0) as scp_counter
| if(%type matches "fcp", 1, 0) as fcp_counter
//| json field=_raw "type" | where %type = "fcp"
| timeslice 1d
| sum(scp_counter) as scp_count, sum(fcp_counter) as fcp_count by _timeslice
| (fcp_count/scp_count) as change_password_ratio
//| count by _timeslice
//| count by %type
```

Password change request fail:success ratio:

```text
(_sourceCategory=wce/prod/auth0 OR _sourceCategory=auth0/prod)
| json field=_raw "type" | where %type = "scpr" or %type = "fcpr"
| if(%type matches "scpr", 1, 0) as scpr_counter
| if(%type matches "fcpr", 1, 0) as fcpr_counter
| timeslice 1d
| sum(scpr_counter) as scpr_count, sum(fcpr_counter) as fcpr_count by _timeslice
| (fcpr_count/scpr_count) as change_password_request_ratio
//| count by _timeslice
//| count by %type
```

Deleted users:

Note how Auth0 logs only the deleted user_id. In other words, we have no idea who the deleted user is, unless we can look up the user_id elsewhere.

```text
_sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com
| parse "*" as jsonobject
| json field=jsonobject "type" as type
| where type matches "sdu"
| fields -jsonobject
```

Missing Business Centre username:

```text
_sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com
| parse "*" as jsonobject
| json field=jsonobject "type" as type
| json field=jsonobject "description" as description
| json field=jsonobject "details.response.body.username" as username
| json field=jsonobject "details.response.body.app_metadata.username" as eidc_username
| where type matches "sapi"
| where eidc_username matches "[]"
| fields -jsonobject
```

Report on failure events:

```text
_sourceCategory=auth0/prod
| json field=_raw "type" as type
| where type matches "f*" and type != "fsa"
| if (type = "f", "Failed Login", type) as type
| if (type = "fapi", "Failed API Operation", type) as type
| if (type = "fc", "Failed By Connector", type) as type
| if (type = "fce", "Failed Change Email", type) as type
| if (type = "fco", "Failed by CORS", type) as type
| if (type = "fcoa", "Failed Cross Origin Authentication", type) as type
| if (type = "fcp", "Failed Change Password", type) as type
| if (type = "fcph", "Failed Post Change Password Hook", type) as type
| if (type = "fcpn", "Failed Change Phone Number", type) as type
| if (type = "fcpr", "Failed Change Password Request", type) as type
| if (type = "fcpro", "Failed Connector Provisioning", type) as type
| if (type = "fcu", "Failed Change Username", type) as type
| if (type = "fd", "Failed Delegation", type) as type
| if (type = "fdu", "Failed User Deletion", type) as type
| if (type matches "fe*", "Failed Exchange", type) as type
| if (type = "flo", "Failed Logout", type) as type
| if (type = "fn", "Failed Sending Notification", type) as type
| if (type = "fp", "Failed Password", type) as type
| if (type = "fs", "Failed Signup", type) as type
| if (type = "fsa", "Failed Silent Authentication", type) as ignore
| if (type = "fu", "Failed Username or Email", type) as type
| if (type = "fui", "Failed User Import", type) as type
| if (type = "fv", "Failed Verification Email", type) as type
| if (type = "fvr", "Failed Verification Email Request", type) as type
| timeslice by 1d
| count by _timeslice, type
| transpose row _timeslice column type
```

"High" login count per user:

```text
_sourceCategory = iam/auth0/tenants/sso.empire-prod.auth0.com
| json "type", "user_name"
| where type matches "s*"
| where !isEmpty(user_name)
| count user_name
| where _count > 1000
```

All logs by type:

```text
_sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com
| json field=_raw "data.type" as auth0_log_event_code
| json field=_raw "data.description"
| lookup event_type from https://raw.githubusercontent.com/dmark/auth0-cli-utilities/master/auth0_log_event_table.csv on auth0_log_event_code=event_code
| lookup event_description from https://raw.githubusercontent.com/dmark/auth0-cli-utilities/master/auth0_log_event_table.csv on auth0_log_event_code=event_code
| count by auth0_log_event_code, event_type, event_description, %data.description
| order by _count
```

Logins outside North America:

```text
_sourceCategory=auth0/prod | json "ip"
| parse "*" as jsonobject
| json field=jsonobject "type" as log_type
| json field=jsonobject "user_name" as username
| where log_type matches "s"
| fields -jsonobject
| lookup latitude, longitude, country_code, country_name, region, city from geo://default on ip = ip
| where country_code != "CA"
| where country_code != "US"
| fields -latitude,longitude,region,country_code
| count by country_name,username
| sort by _count
```

```text
_sourceCategory=auth0/prod | json "ip"
| parse "*" as jsonobject
| json field=jsonobject "type" as log_type
| json field=jsonobject "user_name" as username
| where log_type matches "s"
| fields -jsonobject
| lookup latitude, longitude, country_code, country_name, region, city from geo://default on ip = ip
| where country_code != "CA"
| where country_code != "US"
| count by latitude, longitude, country_code, country_name, region, city, username
| sort by _count
```

Monthly Active Users:

```text
(_sourceCategory=wce/prod/auth0 OR _sourceCategory=auth0/prod) and "empire.ca"
| json field=_raw "type" | where %type = "s"
| json field=_raw "user_id"
| timeslice 4w
| count_distinct(user_id) as users_per_month by _timeslice
| avg(users_per_month)
```

Compliance/Last Login

For a given list of user IDs, when was the last time they logged into one of the specified apps?

```text
_sourceCategory=iam/auth0/tenants/sso.empire-prod.auth0.com
| json field=_raw "data.date" as date
| parseDate(date, "yyyy-MM-dd'T'HH:mm:ss.SSSXXX") as milliseconds
//| json field=_raw "data.client_id" as client_id | where client_id in ("TxNTG19Rv3XGYlMYSTC99RBOFUnl70zK","mGqOniv49ruZ0acIDwR1oF3oszxU0rFq")
| json field=_raw "data.client_name" as client_name | where client_name in ("Empire Portal V2","The Business Centre")
| json field=_raw "data.user_name" as auth0_username
| json field=_raw "data.user_id" as user_id | where user_id in ("auth0|abc123","auth0|def456")
| json field=_raw "data.type" as event_type | where event_type in ("s","ss")
| first(date) as last_login group by auth0_username,client_name,event_type
```

Client Credentials

M2M tokens by client per month.

```
_sourceCategory=iam/auth0/tenants/*
| json field=_raw "data.client_id" as client_id
| json field=_raw "data.client_name" as client_name
| json field=_raw "data.type" as event_type | where event_type in ("seccft")
| timeslice 1d
| formatDate(_timeslice,"yyyy-MM-01") as month
| parseDate(month,"yyyy-MM-dd") as _timeslice
| count by _sourceCategory,_timeslice,client_name,client_id | where _count > 10000
```
