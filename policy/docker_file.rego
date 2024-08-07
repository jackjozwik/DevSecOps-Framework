package main

import future.keywords.in

places_where_secrets_hide := {
	"secret",
	"apikey",
	"access",
}

suspect_runs := {
	"wget",
	"curl",
}

bad_domains := {
	"enter-your-blacklisted-domains.com"
}

# Deny if secrets found in the ENV command
deny_secrets[msg] {
	some x in input
	x.Cmd == "env"
	value := x.Value[0]
	some s in places_where_secrets_hide
	contains(lower(value), s)
	msg := sprintf("secrets found: %q", [value])
}

# Deny if "latest" container image version
deny_latest[msg] {
	some x in input
	x.Cmd == "from"
	value := x.Value[0]
	endswith(lower(value), "latest")
	msg := sprintf("Policy violation: deny_latest. FROM with latest found: %q.", [value])
}

# Deny if no container image version
deny_no_version[msg] {
	some x in input
	x.Cmd == "from"
	value := x.Value[0]
	count(split(value, ":")) == 1
	msg := sprintf("image with no version found: %q", [value])
}


# Deny if APK install in RUN does not specify a repository
deny_run_apk_no_repo[msg] {
    some c in input
    c.Cmd == "run"
    command := c.Value[0]
    subcommand := split(command, " ")[0]
    lower(subcommand) == "apk"
    not contains(lower(command), "--repository")
    msg := sprintf("RUN apk does not specify repo argument, found: %q", [command])
}

# Deny if APK install in RUN specifies a bad repository domain
deny_run_apk_bad_domain[msg] {
    some c in input
    c.Cmd == "run"
    command := c.Value[0]
    subcommand := split(command, " ")[0]
    lower(subcommand) == "apk"
    contains(lower(command), "--repository")
    some d in bad_domains
    contains(lower(command), d)
    msg := sprintf("RUN apk specifies bad repo domain, found: %q", [command])
}

# Deny if cURL or wget is used with RUN and includes a bad domain
deny_curl_wget[msg] {
    some x in input
    x.Cmd == "run"
    value := x.Value[0]
    some run in suspect_runs
    contains(lower(value), run)
    some d in bad_domains
    contains(lower(value), d)
    msg := sprintf("RUN with cURL|wget and bad domain, %q, found: %q", [run, value])
}

# Deny if example.com is used with ADD command
deny_add_domain[msg] {
    some x in input
    x.Cmd == "add"
    value := x.Value[0]
    some d in bad_domains
    contains(lower(value), d)
    msg := sprintf("ADD with bad domain, %q, found: %q", [bad_domains, value])
}

# Deny if example.com is used with ARG command
deny_arg_domain[msg] {
    some x in input
    x.Cmd == "arg"
    value := x.Value[0]
    some d in bad_domains
    contains(lower(value), d)
    msg := sprintf("ARG with bad domain, %q, found: %q", [bad_domains, value])
}